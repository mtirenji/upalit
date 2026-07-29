import "dotenv/config";
import { nanoid } from "nanoid";
import { withDb } from "../db.js";
import { hashPassword, isPasswordStrongEnough } from "./auth.js";

const email = process.env.SEED_ADMIN_EMAIL;
const password = process.env.SEED_ADMIN_PASSWORD;

if (!email || !password) {
  console.error("Set SEED_ADMIN_EMAIL and SEED_ADMIN_PASSWORD in .env before seeding.");
  process.exit(1);
}
if (!isPasswordStrongEnough(password)) {
  console.error("SEED_ADMIN_PASSWORD must be at least 10 characters.");
  process.exit(1);
}

const result = await withDb(async (db) => {
  const existing = db.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  if (existing) return { existed: true };

  const admin = {
    id: nanoid(),
    email: email.toLowerCase(),
    fullName: "Platform Admin",
    passwordHash: await hashPassword(password),
    role: "admin",
    kycStatus: "verified",
    disabled: false,
    createdAt: new Date().toISOString(),
  };
  db.users.push(admin);
  return { created: true };
});

if (result.existed) {
  console.log(`An account with ${email} already exists — nothing to do.`);
} else {
  console.log(`Admin account created for ${email}. Log in, then rotate this password.`);
}
