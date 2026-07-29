# Upalit Backend — Auth + Admin Panel API

A working, tested backend covering account login and an admin panel for
managing investors and property/token listings. Built to sit behind the
Upalit frontend as a starting point — see "What's stubbed vs. real" below
before treating this as production-ready.

## Quick start

```bash
npm install
cp .env.example .env        # then edit JWT secrets + seed admin credentials
npm run seed                # creates your first admin account from .env
npm start                   # http://localhost:4000
```

Verify it's running:
```bash
curl http://localhost:4000/api/health
```

## Auth model

- Passwords hashed with bcrypt (cost factor 12).
- Login issues a short-lived **access token** (15 min default) and a
  longer-lived **refresh token** (7 days default) — both JWTs.
- Send the access token as `Authorization: Bearer <token>` on protected routes.
- When it expires, call `POST /api/auth/refresh` with the refresh token to
  get a new access token, rather than forcing a full re-login.
- Login and registration are rate-limited per IP to slow down brute-force
  and mass account creation.

## Roles

Two roles: `investor` (default on signup) and `admin`. Admin routes are
gated by `requireAuth` + `requireAdmin` middleware — an investor token gets
a `403` on any `/api/admin/*` route.

New accounts also start with `kycStatus: "pending"`. Nothing in this
backend enforces KYC-gated actions yet (e.g. blocking token purchases pre-
verification) — that belongs in the future "buy tokens" endpoint, once you
build it, using the same `req.user.kycStatus` check pattern used here.

## Endpoints

### Public / investor-facing (`/api/auth`)
| Method | Path | Description |
|---|---|---|
| POST | `/register` | Create an investor account |
| POST | `/login` | Get access + refresh tokens |
| POST | `/refresh` | Exchange refresh token for a new access token |
| GET | `/me` | Current user (requires auth) |

### Admin panel (`/api/admin`, all require admin auth)
| Method | Path | Description |
|---|---|---|
| GET | `/users?kycStatus=&q=` | List/search users |
| PATCH | `/users/:id/kyc` | Change KYC status, with audit reason |
| PATCH | `/users/:id/role` | Promote/demote investor ↔ admin |
| PATCH | `/users/:id/disable` | Disable/re-enable an account |
| GET | `/properties` | List all properties |
| POST | `/properties` | Create a property + issue token supply |
| PATCH | `/properties/:id` | Update status, re-appraise valuation |
| DELETE | `/properties/:id` | Delete (draft properties only) |
| GET | `/stats` | Dashboard summary numbers |
| GET | `/audit-log?limit=` | Read the compliance audit trail |

Every admin mutation writes an entry to the audit log (`db.auditLog`) with
who did it, what changed, and when — pull this into the admin panel UI as
an activity feed.

## What's stubbed vs. real

**Real and tested:**
- Password hashing, JWT issuing/verification, rate limiting, role
  enforcement, input validation, audit logging.

**Intentionally stubbed — replace before production:**
- **Database.** `src/db.js` is a single JSON file with a write queue. Fine
  for local dev; not safe for concurrent production traffic. Swap it for
  Postgres (e.g. via Prisma) behind the same `withDb()`/`getDb()` shape so
  the rest of the app doesn't need rewriting.
- **KYC/AML verification.** Admins currently set KYC status manually. In
  production this should integrate a real identity verification provider
  (Persona, Sumsub, etc.), with the admin panel used for manual review of
  edge cases, not primary decisioning.
- **Email verification / password reset.** Not implemented — needed before
  real users touch this.
- **Token purchase / secondary market endpoints.** Out of scope for this
  pass (auth + admin only, as requested) — build these against the same
  `requireAuth` + `kycStatus === "verified"` gate pattern.
- **2FA for admin accounts.** Given the compliance sensitivity of this
  panel, admin logins should require a second factor before production use.

## Security notes for whoever deploys this

- Generate real JWT secrets: `openssl rand -hex 64` for each of
  `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET`. Never reuse the example values.
- Set `CORS_ORIGIN` to your real frontend origin(s) only.
- This API is behind `helmet()` for standard security headers, but you
  should still put it behind HTTPS (e.g. via your hosting provider or a
  reverse proxy) — it does not terminate TLS itself.
- Rotate the seed admin password immediately after first login.
