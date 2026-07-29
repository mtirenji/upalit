// db.js
//
// A minimal file-backed JSON store. This exists so the auth/admin backend
// runs end-to-end without provisioning a real database. Swap this module
// out for a real one (Postgres via Prisma/Knex, etc.) before production —
// see the note at the bottom of this file.

import { readFile, writeFile } from "fs/promises";
import { existsSync, mkdirSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, "..", "data");
const DATA_FILE = path.join(DATA_DIR, "db.json");

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

const EMPTY_DB = {
  users: [],       // { id, email, passwordHash, role, kycStatus, createdAt }
  properties: [],  // { id, name, location, valuationAed, tokenPriceAed, tokensOutstanding, tokensSold, status, lastAppraisalAt, createdAt }
  auditLog: [],     // { id, actorId, action, target, meta, at }
};

// Simple in-process write queue so concurrent requests don't clobber the file.
let writeQueue = Promise.resolve();

async function readDb() {
  if (!existsSync(DATA_FILE)) {
    await writeFile(DATA_FILE, JSON.stringify(EMPTY_DB, null, 2));
    return structuredClone(EMPTY_DB);
  }
  const raw = await readFile(DATA_FILE, "utf-8");
  try {
    return JSON.parse(raw);
  } catch {
    // Corrupt file — don't silently eat data, fail loudly.
    throw new Error(`db.json is not valid JSON (${DATA_FILE})`);
  }
}

async function writeDb(next) {
  writeQueue = writeQueue.then(() =>
    writeFile(DATA_FILE, JSON.stringify(next, null, 2))
  );
  return writeQueue;
}

/**
 * Run a read-modify-write transaction against the JSON store.
 * `fn` receives the current db object, mutates it in place (or returns
 * a replacement), and the result is persisted.
 */
export async function withDb(fn) {
  const db = await readDb();
  const result = await fn(db);
  await writeDb(db);
  return result;
}

export async function getDb() {
  return readDb();
}

/*
 * PRODUCTION NOTE:
 * This file-based store is fine for local development and demoing the
 * auth/admin flow, but it is not safe for concurrent production traffic
 * (no real transactions, no indexing, whole file rewritten on every
 * write). Before going live, replace db.js with a real database client
 * (e.g. Postgres + Prisma) behind the same withDb()/getDb() interface
 * so the rest of the app doesn't need to change.
 */
