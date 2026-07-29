import { Router } from "express";
import { nanoid } from "nanoid";
import { withDb } from "../db.js";
import { requireAuth, requireAdmin } from "../middleware/auth.js";
import { toPublicUser } from "../utils/auth.js";
import { recordAudit } from "../utils/audit.js";

const router = Router();

// Every route below requires a logged-in admin.
router.use(requireAuth, requireAdmin);

const KYC_STATUSES = ["pending", "in_review", "verified", "rejected"];
const PROPERTY_STATUSES = ["draft", "open", "funded", "closed"];

/* --------------------------------- Users --------------------------------- */

/**
 * GET /api/admin/users?kycStatus=&q=
 */
router.get("/users", async (req, res) => {
  const { kycStatus, q } = req.query;
  const db = await withDb(async (db) => db);

  let users = db.users;
  if (kycStatus) users = users.filter((u) => u.kycStatus === kycStatus);
  if (q) {
    const needle = String(q).toLowerCase();
    users = users.filter(
      (u) =>
        u.email.toLowerCase().includes(needle) ||
        u.fullName.toLowerCase().includes(needle)
    );
  }

  res.json({ users: users.map(toPublicUser) });
});

/**
 * PATCH /api/admin/users/:id/kyc
 * Body: { status: "verified" | "rejected" | "in_review" | "pending", note? }
 */
router.patch("/users/:id/kyc", async (req, res) => {
  const { status, note } = req.body || {};
  if (!KYC_STATUSES.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${KYC_STATUSES.join(", ")}` });
  }

  const result = await withDb(async (db) => {
    const user = db.users.find((u) => u.id === req.params.id);
    if (!user) return null;

    const previous = user.kycStatus;
    user.kycStatus = status;
    recordAudit(db, {
      actorId: req.user.id,
      action: "user.kyc_status_change",
      target: user.id,
      meta: { from: previous, to: status, note: note || null },
    });
    return user;
  });

  if (!result) return res.status(404).json({ error: "User not found" });
  res.json({ user: toPublicUser(result) });
});

/**
 * PATCH /api/admin/users/:id/role
 * Body: { role: "investor" | "admin" }
 * Guarded so an admin can't accidentally strip their own admin access.
 */
router.patch("/users/:id/role", async (req, res) => {
  const { role } = req.body || {};
  if (!["investor", "admin"].includes(role)) {
    return res.status(400).json({ error: "role must be 'investor' or 'admin'" });
  }
  if (req.params.id === req.user.id && role !== "admin") {
    return res.status(400).json({ error: "You cannot remove your own admin role" });
  }

  const result = await withDb(async (db) => {
    const user = db.users.find((u) => u.id === req.params.id);
    if (!user) return null;
    const previous = user.role;
    user.role = role;
    recordAudit(db, {
      actorId: req.user.id,
      action: "user.role_change",
      target: user.id,
      meta: { from: previous, to: role },
    });
    return user;
  });

  if (!result) return res.status(404).json({ error: "User not found" });
  res.json({ user: toPublicUser(result) });
});

/**
 * PATCH /api/admin/users/:id/disable
 * Body: { disabled: boolean }
 */
router.patch("/users/:id/disable", async (req, res) => {
  const { disabled } = req.body || {};
  if (typeof disabled !== "boolean") {
    return res.status(400).json({ error: "disabled must be true or false" });
  }
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: "You cannot disable your own account" });
  }

  const result = await withDb(async (db) => {
    const user = db.users.find((u) => u.id === req.params.id);
    if (!user) return null;
    user.disabled = disabled;
    recordAudit(db, {
      actorId: req.user.id,
      action: disabled ? "user.disable" : "user.enable",
      target: user.id,
    });
    return user;
  });

  if (!result) return res.status(404).json({ error: "User not found" });
  res.json({ user: toPublicUser(result) });
});

/* ------------------------------- Properties ------------------------------- */

/**
 * GET /api/admin/properties
 */
router.get("/properties", async (req, res) => {
  const db = await withDb(async (db) => db);
  res.json({ properties: db.properties });
});

/**
 * POST /api/admin/properties
 * Creates a new property listing and issues its initial token supply.
 * Body: { name, location, valuationAed, tokensOutstanding }
 */
router.post("/properties", async (req, res) => {
  const { name, location, valuationAed, tokensOutstanding } = req.body || {};

  if (!name || !location) {
    return res.status(400).json({ error: "name and location are required" });
  }
  if (!Number.isFinite(valuationAed) || valuationAed <= 0) {
    return res.status(400).json({ error: "valuationAed must be a positive number" });
  }
  if (!Number.isInteger(tokensOutstanding) || tokensOutstanding <= 0) {
    return res.status(400).json({ error: "tokensOutstanding must be a positive integer" });
  }

  const property = await withDb(async (db) => {
    const p = {
      id: nanoid(),
      name,
      location,
      valuationAed,
      tokensOutstanding,
      tokensSold: 0,
      tokenPriceAed: Number((valuationAed / tokensOutstanding).toFixed(2)),
      status: "draft",
      lastAppraisalAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      createdBy: req.user.id,
    };
    db.properties.push(p);
    recordAudit(db, {
      actorId: req.user.id,
      action: "property.create",
      target: p.id,
      meta: { name, valuationAed, tokensOutstanding },
    });
    return p;
  });

  res.status(201).json({ property });
});

/**
 * PATCH /api/admin/properties/:id
 * Updates status, valuation (re-appraisal), or listing details.
 * Re-appraising recalculates token price but does not change tokens already sold.
 */
router.patch("/properties/:id", async (req, res) => {
  const { status, valuationAed, name, location } = req.body || {};

  if (status && !PROPERTY_STATUSES.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${PROPERTY_STATUSES.join(", ")}` });
  }
  if (valuationAed !== undefined && (!Number.isFinite(valuationAed) || valuationAed <= 0)) {
    return res.status(400).json({ error: "valuationAed must be a positive number" });
  }

  const result = await withDb(async (db) => {
    const property = db.properties.find((p) => p.id === req.params.id);
    if (!property) return null;

    const changes = {};
    if (status) { changes.status = [property.status, status]; property.status = status; }
    if (name) { property.name = name; }
    if (location) { property.location = location; }
    if (valuationAed !== undefined) {
      changes.valuationAed = [property.valuationAed, valuationAed];
      property.valuationAed = valuationAed;
      property.tokenPriceAed = Number((valuationAed / property.tokensOutstanding).toFixed(2));
      property.lastAppraisalAt = new Date().toISOString();
    }

    recordAudit(db, {
      actorId: req.user.id,
      action: "property.update",
      target: property.id,
      meta: changes,
    });
    return property;
  });

  if (!result) return res.status(404).json({ error: "Property not found" });
  res.json({ property: result });
});

/**
 * DELETE /api/admin/properties/:id
 * Only allowed while still in "draft" — once a property is open for
 * investment it should be closed, not deleted, to preserve the record.
 */
router.delete("/properties/:id", async (req, res) => {
  const result = await withDb(async (db) => {
    const property = db.properties.find((p) => p.id === req.params.id);
    if (!property) return { notFound: true };
    if (property.status !== "draft") {
      return { blocked: true };
    }
    db.properties = db.properties.filter((p) => p.id !== req.params.id);
    recordAudit(db, { actorId: req.user.id, action: "property.delete", target: property.id });
    return { ok: true };
  });

  if (result.notFound) return res.status(404).json({ error: "Property not found" });
  if (result.blocked) {
    return res.status(400).json({
      error: "Only draft properties can be deleted. Close this listing instead.",
    });
  }
  res.status(204).end();
});

/* --------------------------------- Stats ---------------------------------- */

/**
 * GET /api/admin/stats
 * Quick dashboard summary for the admin panel home screen.
 */
router.get("/stats", async (req, res) => {
  const db = await withDb(async (db) => db);

  const totalUsers = db.users.length;
  const verifiedUsers = db.users.filter((u) => u.kycStatus === "verified").length;
  const pendingKyc = db.users.filter((u) => u.kycStatus === "pending" || u.kycStatus === "in_review").length;

  const totalProperties = db.properties.length;
  const openProperties = db.properties.filter((p) => p.status === "open").length;
  const totalValuation = db.properties.reduce((sum, p) => sum + p.valuationAed, 0);
  const totalTokensSoldValue = db.properties.reduce(
    (sum, p) => sum + p.tokensSold * p.tokenPriceAed,
    0
  );

  res.json({
    users: { total: totalUsers, verified: verifiedUsers, pendingKyc },
    properties: { total: totalProperties, open: openProperties, totalValuationAed: totalValuation },
    fundingRaisedAed: totalTokensSoldValue,
  });
});

/* ------------------------------- Audit log -------------------------------- */

/**
 * GET /api/admin/audit-log?limit=100
 * Read-only, append-only trail of admin/compliance-relevant actions.
 */
router.get("/audit-log", async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  const db = await withDb(async (db) => db);
  const entries = [...db.auditLog].reverse().slice(0, limit);
  res.json({ entries });
});

export default router;
