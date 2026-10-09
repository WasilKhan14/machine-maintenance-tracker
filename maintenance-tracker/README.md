# Machine Maintenance Tracker (Full Stack)

Track industrial machines (cranes, generators, motors, gearboxes, pumps), their service schedules, breakdowns, spare parts and maintenance cost.
Node.js + Express + SQLite (built-in `node:sqlite`), scrypt password hashing, signed-token auth, admin / technician roles.

## Run
    npm install
    node server.js
Open http://localhost:4000  (needs Node.js 22.13+)

Demo logins: admin@demo.com / admin123 , tech@demo.com / tech123

## Features
- **Machines:** serial no., manufacturer, hours run, status (Operational / Under Maintenance / Breakdown / Retired), search + filters, add / edit / delete, full history popup
- **Service log:** Preventive / Corrective / Inspection with cost, technician and spare part used (stock is deducted automatically); next service date and Overdue / Due soon alerts
- **Breakdowns:** severity, Open -> Resolved workflow, machine status updates automatically
- **Spare parts:** stock, minimum level, unit cost, stock value, low-stock warnings
- **Dashboard:** availability %, average repair time, total downtime, monthly maintenance cost, top machines by downtime, status chart, activity log (admin)
- **Reports:** printable summary (save as PDF) and CSV export (machines, breakdowns, service history)
- **Team (admin):** promote / demote users; activity log of who changed what
- Dark mode, responsive layout, login rate limiting, input validation, CSV formula-injection guard

## API (summary)
POST /api/register, /api/login | GET/POST /api/machines, GET/PUT/DELETE /api/machines/:id, POST /api/machines/:id/service | GET/POST /api/breakdowns, PUT /api/breakdowns/:id/resolve | GET/POST/PUT/DELETE /api/parts | GET /api/dashboard, /api/activity, /api/users, /api/export/:machines|breakdowns|services

## Deploy
Set environment variable `SECRET` to a long random string in production. Port comes from `PORT`.
