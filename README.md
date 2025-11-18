# Online Attendance Management System

This is a Node.js + Express + SQLite web application for managing classes, students, teachers, sessions, and attendance.

## Project structure

- `server.js` – Express server and API routes
- `db.js` / `schema.sql` – SQLite database and schema
- `public/` – Frontend (HTML, CSS, JavaScript)
- `attendance.db` – Local SQLite database (ignored in Git)

## Prerequisites

- Node.js (v16+ recommended)

## Install and run locally

```bash
npm install
npm start
```

Then open `http://localhost:3000` in your browser.

## GitHub usage

1. Initialize a git repository (if not already):

```bash
git init
git add .
git commit -m "Initial commit"
```

2. Create a new repository on GitHub.
3. Add the GitHub remote and push:

```bash
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

The `.gitignore` file is configured to exclude `node_modules` and the local `attendance.db` database from the repository.
