const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.on('connect', () => {
  console.log('Connected to PostgreSQL database');
});

const SCHEMA_FILE = path.join(__dirname, 'schema.sql');

async function initializeDatabase() {
  try {
    console.log("Loading schema from:", SCHEMA_FILE);
    const schema = fs.readFileSync(SCHEMA_FILE, 'utf8');

    const statements = schema
      .split(';')
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && !s.startsWith('--'));

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const stmt of statements) {
        try {
          await client.query(stmt);
        } catch (e) {
          if (
            /already exists/i.test(e.message) ||
            /duplicate key/i.test(e.message)
          ) {
            continue;
          }
          throw e;
        }
      }
      await client.query('COMMIT');
      console.log("Schema applied successfully!");
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error("Error applying schema:", err);
    process.exit(1);
  }
}

initializeDatabase();

module.exports = {
  query: (text, params) => pool.query(text, params),
  connect: () => pool.connect(),
};
