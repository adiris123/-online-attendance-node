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
// Convert query placeholders (?) to PostgreSQL placeholders ($1, $2, ...)
function convertPlaceholders(sql, params) {
  let paramIndex = 1;
  const convertedSql = sql.replace(/\?/g, () => `$${paramIndex++}`);
  return { sql: convertedSql, params };
}

async function handleDbError(err, res, context = 'Database operation') {
  console.error(`${context} error:`, err);
  return res.status(500).json({ 
    error: 'Database error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
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
app.post('/api/login', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Username, password, and role are required' });
  }

  try {
    const { sql, params } = convertPlaceholders(
      'SELECT id, username, role, class_id, student_id, password FROM users WHERE username = ?',
      [username]
    );
    const result = await db.query(sql, params);
    const user = result.rows[0];

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
        const { sql: updateSql, params: updateParams } = convertPlaceholders(
          'UPDATE users SET password = ? WHERE id = ?',
          [hashed, user.id]
        );
        await db.query(updateSql, updateParams);
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
  } catch (err) {
    return handleDbError(err, res, 'Login');
  }
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
app.get('/api/classes', requireAuth, async (req, res) => {
  try {
    const sql = 'SELECT * FROM classes ORDER BY name';
    const result = await db.query(sql);
    // Always return an array, even if empty
    res.json(Array.isArray(result.rows) ? result.rows : []);
  } catch (err) {
    console.error('GET /api/classes error:', err);
    return handleDbError(err, res, 'Get classes');
  }
});

app.post('/api/classes', requireAuth, requireRole('admin'), async (req, res) => {
  const { name, description } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Class name is required' });
  }
  try {
    const { sql, params } = convertPlaceholders(
      'INSERT INTO classes (name, description) VALUES (?, ?) RETURNING id, name, description',
      [name, description || null]
    );
    const result = await db.query(sql, params);
    if (!result.rows || result.rows.length === 0) {
      return res.status(500).json({ error: 'Failed to create class: no data returned' });
    }
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('POST /api/classes error:', err);
    // Handle unique constraint violations (duplicate class name)
    if (err.code === '23505' || /unique constraint|duplicate key/i.test(err.message)) {
      return res.status(400).json({ error: 'A class with this name already exists' });
    }
    return handleDbError(err, res, 'Create class');
  }
});

// --- Students ---
app.get('/api/students', requireAuth, async (req, res) => {
  const { class_id } = req.query;
  const user = req.user;

  try {
    // Students can only see their own record.
    if (user.role === 'student') {
      if (!user.student_id) {
        return res.json([]);
      }
      const { sql, params } = convertPlaceholders(
        'SELECT * FROM students WHERE id = ? ORDER BY name',
        [user.student_id]
      );
      const result = await db.query(sql, params);
      return res.json(result.rows);
    }

    // Admins and teachers can list students, optionally filtered by class.
    let sql = 'SELECT * FROM students';
    const params = [];
    const where = [];

    if (class_id) {
      where.push(`class_id = $${params.length + 1}`);
      params.push(class_id);
    }

    if (where.length > 0) {
      sql += ' WHERE ' + where.join(' AND ');
    }

    sql += ' ORDER BY name';
    const result = await db.query(sql, params);
    res.json(result.rows);
  } catch (err) {
    return handleDbError(err, res, 'Get students');
  }
});

app.post('/api/students', requireAuth, requireRole('admin'), async (req, res) => {
  const { name, roll_number, class_id } = req.body;
  if (!name || !class_id) {
    return res.status(400).json({ error: 'Student name and class_id are required' });
  }

  const classIdInt = parseInt(class_id, 10);
  if (isNaN(classIdInt) || classIdInt <= 0) {
    return res.status(400).json({ error: 'Invalid class_id' });
  }

  try {
    // Validate class exists
    const { sql: checkSql, params: checkParams } = convertPlaceholders(
      'SELECT id FROM classes WHERE id = ?',
      [classIdInt]
    );
    const checkResult = await db.query(checkSql, checkParams);
    
    if (checkResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid class_id: class does not exist' });
    }

    const { sql, params } = convertPlaceholders(
      'INSERT INTO students (name, roll_number, class_id) VALUES (?, ?, ?) RETURNING id',
      [name, roll_number || null, classIdInt]
    );
    const result = await db.query(sql, params);
    res.status(201).json({ id: result.rows[0].id, name, roll_number: roll_number || null, class_id: classIdInt });
  } catch (err) {
    return handleDbError(err, res, 'Add student');
  }
});

// --- Teachers ---
// Teachers are stored in the users table with role = 'teacher'.
// These endpoints let admins list and create teacher accounts.
app.get('/api/teachers', requireAuth, requireRole('admin'), async (req, res) => {
  const { class_id } = req.query;

  try {
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
      sql += ` AND u.class_id = $${params.length + 1}`;
      params.push(class_id);
    }

    sql += ' ORDER BY COALESCE(u.display_name, u.username)';
    const result = await db.query(sql, params);
    res.json(result.rows);
  } catch (err) {
    return handleDbError(err, res, 'Get teachers');
  }
});

app.post('/api/teachers', requireAuth, requireRole('admin'), async (req, res) => {
  const { username, display_name, password, class_id, email, phone, subject, experience } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required for a teacher account' });
  }

  // Validate username format (basic)
  if (username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: 'Username must be between 3 and 50 characters' });
  }

  try {
    // Check if username already exists
    const { sql: checkSql, params: checkParams } = convertPlaceholders(
      'SELECT id FROM users WHERE username = ?',
      [username]
    );
    const existingResult = await db.query(checkSql, checkParams);
    
    if (existingResult.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Validate class_id if provided
    if (class_id) {
      const classIdInt = parseInt(class_id, 10);
      if (isNaN(classIdInt) || classIdInt <= 0) {
        return res.status(400).json({ error: 'Invalid class_id' });
      }

      const { sql: classCheckSql, params: classCheckParams } = convertPlaceholders(
        'SELECT id FROM classes WHERE id = ?',
        [classIdInt]
      );
      const classResult = await db.query(classCheckSql, classCheckParams);
      
      if (classResult.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid class_id: class does not exist' });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const { sql, params } = convertPlaceholders(
      'INSERT INTO users (username, password, role, display_name, class_id, email, phone, subject, experience) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id',
      [username, hashedPassword, 'teacher', display_name || null, class_id || null, email || null, phone || null, subject || null, experience || null]
    );
    const result = await db.query(sql, params);

    res.status(201).json({
      id: result.rows[0].id,
      username,
      display_name: display_name || null,
      class_id: class_id || null,
      email: email || null,
      phone: phone || null,
      subject: subject || null,
      experience: experience || null,
    });
  } catch (err) {
    return handleDbError(err, res, 'Add teacher');
  }
});

// --- Dashboard stats ---

app.get('/api/dashboard/admin', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const sql = `
      SELECT
        (SELECT COUNT(*) FROM students) AS total_students,
        (SELECT COUNT(*) FROM users WHERE role = 'teacher') AS total_teachers,
        (SELECT COUNT(*) FROM classes) AS total_classes,
        0 AS active_policies
    `;

    const result = await db.query(sql);
    const row = result.rows[0] || {
      total_students: 0,
      total_teachers: 0,
      total_classes: 0,
      active_policies: 0,
    };

    res.json(row);
  } catch (err) {
    return handleDbError(err, res, 'Admin dashboard');
  }
});

app.get('/api/dashboard/teacher', requireAuth, requireRole('teacher'), async (req, res) => {
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

  try {
    const today = new Date().toISOString().slice(0, 10);
    const { sql, params } = convertPlaceholders(
      `SELECT
        c.id AS class_id,
        c.name AS class_name,
        (SELECT COUNT(*) FROM students s WHERE s.class_id = c.id) AS student_count,
        (SELECT COUNT(*) FROM sessions sess WHERE sess.class_id = c.id AND sess.date = ?) AS today_sessions
      FROM classes c
      WHERE c.id = ?`,
      [today, classId]
    );

    const result = await db.query(sql, params);
    const row = result.rows[0];

    if (!row) {
      return res.json({
        class_id: classId,
        class_name: null,
        student_count: 0,
        today_sessions: 0,
      });
    }

    res.json(row);
  } catch (err) {
    return handleDbError(err, res, 'Teacher dashboard');
  }
});

// --- Sessions ---
// Admins can view all sessions (for reporting/management).
// Teachers can view sessions for any class in the system (multi-class access).
// Students remain scoped to their own class.
app.get('/api/sessions', requireAuth, async (req, res) => {
  const { class_id } = req.query;
  const user = req.user;

  try {
    let sql = 'SELECT s.*, c.name as class_name FROM sessions s JOIN classes c ON s.class_id = c.id';
    const params = [];
    const where = [];

    if (user.role === 'admin' || user.role === 'teacher') {
      // Admins and teachers can optionally filter by any class_id.
      if (class_id) {
        where.push(`s.class_id = $${params.length + 1}`);
        params.push(class_id);
      }
    } else if (user.role === 'student') {
      // Students are still restricted to sessions for their own class.
      if (!user.class_id) {
        return res.json([]);
      }
      where.push(`s.class_id = $${params.length + 1}`);
      params.push(user.class_id);
    }

    if (where.length > 0) {
      sql += ' WHERE ' + where.join(' AND ');
    }

    sql += ' ORDER BY date DESC, s.id DESC';
    const result = await db.query(sql, params);
    res.json(result.rows);
  } catch (err) {
    return handleDbError(err, res, 'Get sessions');
  }
});

// NOTE: Only teachers create classroom sessions. Admin can manage/view but not create.
app.post('/api/sessions', requireAuth, requireRole('teacher'), async (req, res) => {
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

  try {
    // Validate class exists
    const { sql: checkSql, params: checkParams } = convertPlaceholders(
      'SELECT id FROM classes WHERE id = ?',
      [classIdInt]
    );
    const checkResult = await db.query(checkSql, checkParams);
    
    if (checkResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid class_id: class does not exist' });
    }

    const { sql, params } = convertPlaceholders(
      'INSERT INTO sessions (class_id, date, topic) VALUES (?, ?, ?) RETURNING id',
      [classIdInt, date, topic || null]
    );
    const result = await db.query(sql, params);
    res.status(201).json({ id: result.rows[0].id, class_id: classIdInt, date, topic: topic || null });
  } catch (err) {
    return handleDbError(err, res, 'Create session');
  }
});

// --- Attendance ---
// Mark attendance for one or many students
// NOTE: Only teachers can mark attendance. Admins can view reports but cannot mark.
app.post('/api/attendance', requireAuth, requireRole('teacher'), async (req, res) => {
  const { session_id, records } = req.body;

  if (!session_id || !Array.isArray(records) || records.length === 0) {
    return res.status(400).json({ error: 'session_id and an array of records are required' });
  }

  // Validate session_id is integer
  const sessionIdInt = parseInt(session_id, 10);
  if (isNaN(sessionIdInt) || sessionIdInt <= 0) {
    return res.status(400).json({ error: 'Invalid session_id' });
  }

  const client = await db.connect();
  try {
    await client.query('BEGIN');

    // Get session class_id
    const { sql: sessionSql, params: sessionParams } = convertPlaceholders(
      'SELECT class_id FROM sessions WHERE id = ?',
      [sessionIdInt]
    );
    const sessionResult = await client.query(sessionSql, sessionParams);
    
    if (sessionResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Invalid session_id' });
    }

    const sessionClassId = sessionResult.rows[0].class_id;

    // Validate all student_ids belong to the session's class
    const studentIds = records
      .map(r => parseInt(r.student_id, 10))
      .filter(id => !isNaN(id) && id > 0);
    
    if (studentIds.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No valid student_ids provided' });
    }

    // Validate status values
    const validStatuses = ['present', 'absent'];
    const invalidRecords = records.filter(r => !validStatuses.includes(String(r.status).toLowerCase()));
    if (invalidRecords.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Invalid status values. Must be "present" or "absent"' });
    }

    // Check all students belong to the session's class
    const placeholders = studentIds.map((_, i) => `$${i + 1}`).join(',');
    const checkSql = `SELECT id FROM students WHERE id IN (${placeholders}) AND class_id = $${studentIds.length + 1}`;
    const checkResult = await client.query(checkSql, [...studentIds, sessionClassId]);
    
    if (checkResult.rows.length !== studentIds.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Some students do not belong to this session\'s class' });
    }

    // Filter valid records
    const validRecords = records.filter(rec => {
      const studentId = parseInt(rec.student_id, 10);
      const status = String(rec.status).toLowerCase();
      return !isNaN(studentId) && studentId > 0 && validStatuses.includes(status);
    });

    if (validRecords.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No valid records to save' });
    }

    // Use INSERT ... ON CONFLICT to preserve marked_at timestamp on updates
    const upsertSql = `
      INSERT INTO attendance (session_id, student_id, status, marked_at)
      VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
      ON CONFLICT(session_id, student_id) 
      DO UPDATE SET status = EXCLUDED.status
    `;

    for (const rec of validRecords) {
      const studentId = parseInt(rec.student_id, 10);
      const status = String(rec.status).toLowerCase();
      await client.query(upsertSql, [sessionIdInt, studentId, status]);
    }

    await client.query('COMMIT');
    res.status(201).json({ message: 'Attendance saved successfully' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return handleDbError(err, res, 'Save attendance');
  } finally {
    client.release();
  }
});

// Get attendance by session
app.get('/api/attendance/by-session', requireAuth, requireRole('admin', 'teacher'), async (req, res) => {
  const { session_id } = req.query;
  if (!session_id) {
    return res.status(400).json({ error: 'session_id is required' });
  }

  try {
    const { sql: checkSql, params: checkParams } = convertPlaceholders(
      'SELECT class_id FROM sessions WHERE id = ?',
      [session_id]
    );
    const checkResult = await db.query(checkSql, checkParams);
    
    if (checkResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid session_id' });
    }

    const { sql, params } = convertPlaceholders(
      `SELECT a.id, a.status, a.marked_at,
             s.id AS student_id, s.name AS student_name, s.roll_number,
             sess.date, sess.topic, c.name AS class_name
      FROM attendance a
      JOIN students s ON a.student_id = s.id
      JOIN sessions sess ON a.session_id = sess.id
      JOIN classes c ON sess.class_id = c.id
      WHERE a.session_id = ?
      ORDER BY s.name`,
      [session_id]
    );
    const result = await db.query(sql, params);
    res.json(result.rows);
  } catch (err) {
    return handleDbError(err, res, 'Get attendance by session');
  }
});

// --- Reports ---
// Attendance for a single student across sessions
app.get('/api/reports/by-student', requireAuth, async (req, res) => {
  const { student_id } = req.query;
  if (!student_id) {
    return res.status(400).json({ error: 'student_id is required' });
  }

  const studentIdInt = parseInt(student_id, 10);
  if (isNaN(studentIdInt) || studentIdInt <= 0) {
    return res.status(400).json({ error: 'Invalid student_id' });
  }

  const user = req.user;

  const runQuery = async () => {
    try {
      const { sql, params } = convertPlaceholders(
        `SELECT a.status, a.marked_at,
               sess.id AS session_id, sess.date, sess.topic,
               c.id AS class_id, c.name AS class_name
        FROM attendance a
        JOIN sessions sess ON a.session_id = sess.id
        JOIN classes c ON sess.class_id = c.id
        WHERE a.student_id = ?
        ORDER BY sess.date DESC, sess.id DESC`,
        [studentIdInt]
      );
      const result = await db.query(sql, params);
      return res.json(result.rows);
    } catch (err) {
      return handleDbError(err, res, 'Get student report');
    }
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
app.get('/api/reports/summary-by-class', requireAuth, async (req, res) => {
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

  try {
    // FIXED: Only count sessions where attendance was actually marked
    const { sql, params } = convertPlaceholders(
      `SELECT 
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
      ORDER BY st.name`,
      [classIdInt]
    );
    const result = await db.query(sql, params);
    res.json(result.rows);
  } catch (err) {
    return handleDbError(err, res, 'Get class summary');
  }
});

// Export: Student report (CSV / PDF)
app.get('/api/reports/by-student/export', requireAuth, async (req, res) => {
  const { student_id, format = 'csv' } = req.query;
  if (!student_id) {
    return res.status(400).json({ error: 'student_id is required' });
  }

  const user = req.user;

  const runQuery = async () => {
    try {
      const { sql, params } = convertPlaceholders(
        `SELECT a.status, a.marked_at,
               sess.id AS session_id, sess.date, sess.topic,
               c.id AS class_id, c.name AS class_name
        FROM attendance a
        JOIN sessions sess ON a.session_id = sess.id
        JOIN classes c ON sess.class_id = c.id
        WHERE a.student_id = ?
        ORDER BY sess.date DESC, sess.id DESC`,
        [student_id]
      );
      const result = await db.query(sql, params);
      const rows = result.rows;

      if (format === 'pdf') {
        return sendStudentReportPdf(res, rows, {
          filename: `student-${student_id}-report.pdf`,
        });
      }

      return sendStudentReportCsv(res, rows, `student-${student_id}-report`);
    } catch (err) {
      return handleDbError(err, res, 'Export student report');
    }
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
app.get('/api/reports/summary-by-class/export', requireAuth, async (req, res) => {
  const { class_id, format = 'csv' } = req.query;
  if (!class_id) {
    return res.status(400).json({ error: 'class_id is required' });
  }

  const user = req.user;

  if (user.role === 'student') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    const { sql, params } = convertPlaceholders(
      `SELECT st.id AS student_id,
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
      ORDER BY st.name`,
      [class_id]
    );
    const result = await db.query(sql, params);
    const rows = result.rows;

    if (format === 'pdf') {
      return sendClassSummaryPdf(res, rows, {
        filename: `class-${class_id}-summary.pdf`,
      });
    }

    return sendClassSummaryCsv(res, rows, `class-${class_id}-summary`);
  } catch (err) {
    return handleDbError(err, res, 'Export class summary');
  }
});

// Fallback route - serve index
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
