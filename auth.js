import { Router } from "express";
import rateLimit from "express-rate-limit";
import { nanoid } from "nanoid";
import { withDb } from "../db.js";
import {
  hashPassword,
  verifyPassword,
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  toPublicUser,
  isPasswordStrongEnough,
  isValidEmail,
} from "../utils/auth.js";
import { requireAuth } from "../middleware/auth.js";
import { recordAudit } from "../utils/audit.js";

const router = Router();

// Slow down credential-stuffing / brute-force attempts against login.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Try again in a few minutes." },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many accounts created from this network. Try again later." },
});

/**
 * POST /api/auth/register
 * Creates an investor account. KYC/eligibility screening happens
 * separately (kycStatus starts "pending") — this endpoint only handles
 * credentials.
 */
router.post("/register", registerLimiter, async (req, res) => {
  const { email, password, fullName } = req.body || {};

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "A valid email address is required" });
  }
  if (!isPasswordStrongEnough(password)) {
    return res.status(400).json({ error: "Password must be at least 10 characters" });
  }
  if (!fullName || typeof fullName !== "string" || fullName.trim().length < 2) {
    return res.status(400).json({ error: "Full name is required" });
  }

  try {
    const result = await withDb(async (db) => {
      const existing = db.users.find(
        (u) => u.email.toLowerCase() === email.toLowerCase()
      );
      if (existing) {
        return { conflict: true };
      }

      const user = {
        id: nanoid(),
        email: email.toLowerCase(),
        fullName: fullName.trim(),
        passwordHash: await hashPassword(password),
        role: "investor",
        kycStatus: "pending", // pending -> in_review -> verified | rejected
        disabled: false,
        createdAt: new Date().toISOString(),
      };
      db.users.push(user);
      recordAudit(db, { actorId: user.id, action: "user.register", target: user.id });
      return { user };
    });

    if (result.conflict) {
      // Same message as "success" territory is avoided here deliberately —
      // email enumeration is a lower concern than user confusion for this
      // flow, but swap to a generic message if that trade-off changes.
      return res.status(409).json({ error: "An account with this email already exists" });
    }

    const accessToken = signAccessToken(result.user);
    const refreshToken = signRefreshToken(result.user);

    res.status(201).json({
      user: toPublicUser(result.user),
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.error("register failed:", err);
    res.status(500).json({ error: "Could not create account" });
  }
});

/**
 * POST /api/auth/login
 */
router.post("/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};

  if (!isValidEmail(email) || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const db = await withDb(async (db) => db); // read-only, but keep it consistent
  const user = db.users.find((u) => u.email.toLowerCase() === email.toLowerCase());

  // Always run bcrypt.compare even on "user not found" so response timing
  // doesn't reveal whether an email is registered.
  const passwordHash = user?.passwordHash ?? "$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinva";
  const passwordOk = await verifyPassword(password ?? "", passwordHash);

  if (!user || !passwordOk) {
    return res.status(401).json({ error: "Invalid email or password" });
  }
  if (user.disabled) {
    return res.status(403).json({ error: "This account has been disabled" });
  }

  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);

  await withDb(async (db) => {
    const u = db.users.find((x) => x.id === user.id);
    recordAudit(db, { actorId: u.id, action: "user.login", target: u.id });
  });

  res.json({
    user: toPublicUser(user),
    accessToken,
    refreshToken,
  });
});

/**
 * POST /api/auth/refresh
 * Exchanges a valid refresh token for a new access token.
 */
router.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) {
    return res.status(400).json({ error: "refreshToken is required" });
  }

  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch {
    return res.status(401).json({ error: "Invalid or expired refresh token" });
  }

  const db = await withDb(async (db) => db);
  const user = db.users.find((u) => u.id === payload.sub);
  if (!user || user.disabled) {
    return res.status(401).json({ error: "User no longer active" });
  }

  res.json({ accessToken: signAccessToken(user) });
});

/**
 * GET /api/auth/me
 */
router.get("/me", requireAuth, async (req, res) => {
  res.json({ user: req.user });
});

export default router;
