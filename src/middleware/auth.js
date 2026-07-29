import { verifyAccessToken } from "../utils/auth.js";
import { getDb } from "../db.js";

/**
 * Requires a valid access token. Attaches req.user (full user record,
 * minus password hash) on success.
 */
export async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Missing or malformed authorization header" });
  }

  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch {
    return res.status(401).json({ error: "Invalid or expired access token" });
  }

  const db = await getDb();
  const user = db.users.find((u) => u.id === payload.sub);
  if (!user) {
    return res.status(401).json({ error: "User no longer exists" });
  }
  if (user.disabled) {
    return res.status(403).json({ error: "Account is disabled" });
  }

  const { passwordHash, ...safeUser } = user;
  req.user = safeUser;
  next();
}

/**
 * Requires req.user.role to be one of `roles`. Must run after requireAuth.
 */
export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }
    next();
  };
}

export const requireAdmin = requireRole("admin");
