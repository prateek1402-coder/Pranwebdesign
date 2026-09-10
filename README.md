# PRAN Technologies — Backend Edition

Your original PRAN website is kept as the frontend, but its demo `localStorage` data has been replaced with a real Node.js/Express backend and SQLite database.

## What now works
- Customer account signup/login
- Admin + Employee + Customer roles
- Passwords hashed with bcrypt
- Login protected by rate limiting
- HTTP-only signed session cookie
- Project registration saved to `data/pran.db`
- Contact/consultation requests saved to database
- Admin dashboard can see customers, employees, projects and project requests
- Admin can update project status/progress
- Admin can add employees and enable/disable accounts
- Tasks and task status are stored on server
- Messages are stored on server
- No demo passwords are hard-coded into the frontend

## Windows setup
1. Install Node.js 20+ (LTS recommended).
2. Copy `.env.example` to `.env`.
3. Open `.env` and set:
   - `JWT_SECRET` to a long random string (32+ characters)
   - `ADMIN_EMAIL` / `ADMIN_PASSWORD`
   - `EMPLOYEE_EMAIL` / `EMPLOYEE_PASSWORD`
4. Open this folder in Command Prompt or PowerShell.
5. Run:
   `npm install`
6. Start:
   `npm start`
7. Open:
   `http://localhost:3000`

The SQLite database is created automatically at `data/pran.db`.

## Important
Do not upload `.env` or `data/pran.db` to GitHub. The included `.gitignore` already blocks them.

For production hosting, also use HTTPS and a production-grade secret in `JWT_SECRET`.


### Project assignment
Admins can assign or reassign active employees from Dashboard → Projects. Employees see only projects assigned to their account under My Projects.
