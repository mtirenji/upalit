import { nanoid } from "nanoid";

/**
 * Records an admin/compliance-relevant action inside an active withDb()
 * transaction. Call this from within the same `db` mutation as the change
 * itself so the log entry and the change are persisted together.
 */
export function recordAudit(db, { actorId, action, target = null, meta = {} }) {
  db.auditLog.push({
    id: nanoid(),
    actorId,
    action,
    target,
    meta,
    at: new Date().toISOString(),
  });
}
