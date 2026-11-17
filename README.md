# CPS Digital Diary

A Cloudflare Workers + D1 school diary application for Capital Public School. Includes public student signup, teacher signup with admin approval or invite code, admin-managed custom classes (no sections), daily diary entries, homework completion, announcements, and light/dark/pink/custom themes.

## Requirements
- Cloudflare account
- Node.js and npm on your development machine (only to run Wrangler/deploy; no Node.js application server)
- Cloudflare D1 database

## 1. Install and create the database

```bash
npm install
npx wrangler login
npx wrangler d1 create cps-diary-db
```

Copy the returned database ID into `wrangler.toml`, replacing `REPLACE_WITH_YOUR_D1_DATABASE_ID`.

Apply the schema:

```bash
npm run db:local
npm run db:remote
```

## 2. Configure the admin bootstrap secret

Choose a long random secret and set it as a Worker secret:

```bash
npx wrangler secret put BOOTSTRAP_SECRET
```

Set it to the value you chose. This secret is only used once to create the first admin account. Bootstrap endpoint locks itself after an admin exists.

## 3. Run locally

```bash
npm run dev
```

## 4. Create the first admin

While `wrangler dev` is running, send a POST request to `http://localhost:8787/api/admin/bootstrap` with header `x-bootstrap-secret: YOUR_SECRET` and JSON body:

```json
{"name":"CPS Administrator","email":"admin@example.com","password":"Use-A-Long-Unique-Password-Here"}
```

You can use an API client or browser developer console. Do not share the bootstrap secret or admin password.

## 5. Deploy

```bash
npm run deploy
```

Cloudflare will provide a `workers.dev` URL. Add a custom domain later in the Cloudflare dashboard if desired.

## Roles and access
- Anyone can register a student account after choosing an active class.
- Anyone can request a teacher account. It stays pending until an admin approves it, unless a valid teacher invite code is supplied during signup.
- Admins create the custom class list. There are no sections.
- Teachers and admins can publish diary entries. Students see entries for their own class and can mark homework complete.
- Admins can manage users, classes, and teacher invite codes.

## Important production checklist
- Configure a custom domain and HTTPS (Cloudflare serves HTTPS by default on deployed domains).
- Add a school-approved privacy notice and contact details before inviting students.
- Establish parent/school consent and data-retention rules for student accounts.
- Back up the D1 database regularly.
- Consider adding email verification, password reset, audit logs, CSRF protections for any future cross-site integrations, and rate limiting before broad public launch.
- Google sign-in is not included in this first build; it requires a Google OAuth client and callback configuration.
