const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

// PostgreSQL connection configuration
// Uses DATABASE_URL environment variable (required for Render deployment)
// For local development, set DATABASE_URL or use: postgresql://user:password@localhost:5432/attendance
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || `postgresql://${process.env.DB_USER || 'postgres'}:${process.env.DB_PASSWORD || 'postgres'}@${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 5432}/${process.env.DB_NAME || 'attendance'}`,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Test connection
pool.on('connect', () => {
  console.log('Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle PostgreSQL client', err);
  process.exit(-1);
});

const SCHEMA_FILE = path.join(__dirname, 'schema.sql');

// Initialize database schema
async function initializeDatabase() {
  try {
    const schemaSql = fs.readFileSync(SCHEMA_FILE, 'utf8');
    
    // Split schema into individual statements (PostgreSQL requires separate statements)
    const statements = schemaSql
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith('--'));

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // Execute statements with better error handling
      for (const statement of statements) {
        if (statement.trim()) {
          try {
            await client.query(statement);
          } catch (stmtErr) {
            // Ignore non-critical errors:
            // - "already exists" for CREATE TABLE IF NOT EXISTS
            // - "duplicate key" for INSERT ... ON CONFLICT DO NOTHING
            // - "does not exist" for SELECT setval (sequence might not exist yet)
            const errorMsg = stmtErr.message.toLowerCase();
            const isNonCritical = 
              /already exists/i.test(errorMsg) ||
              /duplicate key|violates unique constraint/i.test(errorMsg) ||
              /does not exist/i.test(errorMsg) && /setval/i.test(statement.toLowerCase());
            
            if (!isNonCritical) {
              // Re-throw critical errors
              throw stmtErr;
            }
            // Log non-critical warnings for debugging
            if (process.env.NODE_ENV === 'development') {
              console.warn('Schema statement warning (non-critical):', stmtErr.message);
            }
          }
        }
      }

      // Lightweight migrations: ensure extra teacher detail columns exist on users table.
      // These ALTERs will fail with "duplicate column name" after the first run; we ignore that.
      const alterStatements = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS subject TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS experience TEXT",
      ];

      for (const sql of alterStatements) {
        try {
          await client.query(sql);
        } catch (alterErr) {
          // Ignore "duplicate column" errors
          if (!/already exists/i.test(alterErr.message)) {
            console.error('Migration error:', alterErr.message);
          }
        }
      }

      await client.query('COMMIT');
      console.log('Database schema ensured.');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {}); // Ignore rollback errors
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Error applying database schema:', err.message);
    throw err;
  }
}

// Initialize on startup
initializeDatabase().catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});

// Export pool for use in server.js
module.exports = pool;
