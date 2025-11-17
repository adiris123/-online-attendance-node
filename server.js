const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const PDFDocument = require('pdfkit');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const sessions = new Map();

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Helpers ---
function handleDbCallback(res, successStatus = 200, transform = (rows) => rows) {
  return (err, result) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    res.status(successStatus).json(transform(result));
  };
}

function getUserFromRequest(req) {
  const token = req.headers['x-auth-token'] || req.query.token;
  if (!token) return null;
  return sessions.get(token) || null;
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
  sessions.set(token, safeUser);
  return { token, user: safeUser };
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
  db.get(sql, [username], (err, user) => {
    if (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    if (String(user.role) !== String(role)) {
      return res
        .status(400)
        .json({ error: 'Incorrect role selected. Please choose the correct role.' });
    }

    const { token, user: sessionUser } = createSession(user);
    res.json({ message: 'Login successful', user: sessionUser, token });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// --- Classes ---
app.get('/api/classes', requireAuth, (req, res) => {
  const user = req.user;
  let sql = 'SELECT * FROM classes';
  const params = [];

  if (user.role === 'teacher' || user.role === 'student') {
    if (user.class_id) {
      sql += ' WHERE id = ?';
      params.push(user.class_id);
    } else {
      return res.json([]);
    }
  }

  sql += ' ORDER BY name';
  db.all(sql, params, handleDbCallback(res));
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

  let sql = 'SELECT * FROM students';
  const params = [];
  const where = [];

  if (user.role === 'admin') {
    if (class_id) {
      where.push('class_id = ?');
      params.push(class_id);
    }
  } else if (user.role === 'teacher') {
    if (!user.class_id) {
      return res.json([]);
    }
    where.push('class_id = ?');
    params.push(user.class_id);
  } else if (user.role === 'student') {
    if (!user.student_id) {
      return res.json([]);
    }
    where.push('id = ?');
    params.push(user.student_id);
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
  const sql = 'INSERT INTO students (name, roll_number, class_id) VALUES (?, ?, ?)';
  db.run(sql, [name, roll_number || null, class_id], function (err) {
    if (err) {
      console.error('Add student error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.status(201).json({ id: this.lastID, name, roll_number: roll_number || null, class_id });
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

  const sql = 'INSERT INTO users (username, password, role, display_name, class_id, email, phone, subject, experience) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
  db.run(sql, [username, password, 'teacher', display_name || null, class_id || null, email || null, phone || null, subject || null, experience || null], function (err) {
    if (err) {
      console.error('Add teacher error:', err);
      return res.status(500).json({ error: 'Database error' });
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
});

// --- Sessions ---
// Admins can view all sessions (for reporting/management).
// Teachers can view only their own class sessions.
app.get('/api/sessions', requireAuth, (req, res) => {
  const { class_id } = req.query;
  const user = req.user;

  let sql = 'SELECT s.*, c.name as class_name FROM sessions s JOIN classes c ON s.class_id = c.id';
  const params = [];
  const where = [];

  if (user.role === 'admin') {
    if (class_id) {
      where.push('s.class_id = ?');
      params.push(class_id);
    }
  } else if (user.role === 'teacher' || user.role === 'student') {
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

  if (user.role === 'teacher') {
    if (!user.class_id || String(user.class_id) !== String(class_id)) {
      return res.status(403).json({ error: 'Teachers can only create sessions for their own class' });
    }
  }

  const sql = 'INSERT INTO sessions (class_id, date, topic) VALUES (?, ?, ?)';
  db.run(sql, [class_id, date, topic || null], function (err) {
    if (err) {
      console.error('Create session error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.status(201).json({ id: this.lastID, class_id, date, topic: topic || null });
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

  db.get('SELECT class_id FROM sessions WHERE id = ?', [session_id], (err, sessionRow) => {
    if (err) {
      console.error('Lookup session error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!sessionRow) {
      return res.status(400).json({ error: 'Invalid session_id' });
    }

    if (req.user.role === 'teacher') {
      if (!req.user.class_id || req.user.class_id !== sessionRow.class_id) {
        return res.status(403).json({ error: 'You cannot mark attendance for this session' });
      }
    }

    const stmt = db.prepare('INSERT OR REPLACE INTO attendance (session_id, student_id, status) VALUES (?, ?, ?)');

    db.serialize(() => {
      db.run('BEGIN TRANSACTION');
      try {
        for (const rec of records) {
          if (!rec.student_id || !rec.status) continue;
          stmt.run([session_id, rec.student_id, rec.status]);
        }
        db.run('COMMIT', (commitErr) => {
          if (commitErr) {
            console.error('Commit error:', commitErr);
            return res.status(500).json({ error: 'Failed to save attendance' });
          }
          res.status(201).json({ message: 'Attendance saved' });
        });
      } catch (e) {
        console.error('Attendance transaction error:', e);
        db.run('ROLLBACK');
        res.status(500).json({ error: 'Failed to save attendance' });
      } finally {
        stmt.finalize();
      }
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

    if (req.user.role === 'teacher') {
      if (!req.user.class_id || req.user.class_id !== sessionRow.class_id) {
        return res.status(403).json({ error: 'You cannot view attendance for this session' });
      }
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

    db.all(sql, [student_id], handleDbCallback(res));
  };

  if (user.role === 'admin') {
    return runQuery();
  }

  if (user.role === 'student') {
    if (!user.student_id || String(user.student_id) !== String(student_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return runQuery();
  }

  if (user.role === 'teacher') {
    if (!user.class_id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    db.get('SELECT class_id FROM students WHERE id = ?', [student_id], (err, row) => {
      if (err) {
        console.error('Lookup student error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row) {
        return res.status(404).json({ error: 'Student not found' });
      }
      if (row.class_id !== user.class_id) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      return runQuery();
    });
    return;
  }

  return res.status(403).json({ error: 'Forbidden' });
});

// Summary by class: per-student counts
app.get('/api/reports/summary-by-class', requireAuth, (req, res) => {
  const { class_id } = req.query;
  if (!class_id) {
    return res.status(400).json({ error: 'class_id is required' });
  }

  const user = req.user;

  if (user.role === 'teacher') {
    if (!user.class_id || String(user.class_id) !== String(class_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
  } else if (user.role === 'student') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const sql = `
    SELECT st.id AS student_id,
           st.name AS student_name,
           st.roll_number,
           SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) AS presents,
           COUNT(a.id) AS total
    FROM students st
    LEFT JOIN attendance a ON st.id = a.student_id
    LEFT JOIN sessions sess ON a.session_id = sess.id
    WHERE st.class_id = ?
    GROUP BY st.id, st.name, st.roll_number
    ORDER BY st.name
  `;

  db.all(sql, [class_id], handleDbCallback(res));
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
    if (!user.class_id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    db.get('SELECT class_id FROM students WHERE id = ?', [student_id], (err, row) => {
      if (err) {
        console.error('Lookup student error (export):', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row) {
        return res.status(404).json({ error: 'Student not found' });
      }
      if (row.class_id !== user.class_id) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      return runQuery();
    });
    return;
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

  if (user.role === 'teacher') {
    if (!user.class_id || String(user.class_id) !== String(class_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
  } else if (user.role === 'student') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const sql = `
    SELECT st.id AS student_id,
           st.name AS student_name,
           st.roll_number,
           SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) AS presents,
           COUNT(a.id) AS total
    FROM students st
    LEFT JOIN attendance a ON st.id = a.student_id
    LEFT JOIN sessions sess ON a.session_id = sess.id
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
