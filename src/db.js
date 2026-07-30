import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, '../data');
const DB_PATH = path.join(DATA_DIR, 'db.json');

let db = null;
let writeQueue = Promise.resolve();
let isInitialized = false;

const defaultDb = () => ({
  users: [],
  properties: [],
  tokens: [],
  auditLog: [],
  _meta: {
    version: '1.0.0',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
});

export const getDb = () => {
  if (!db) throw new Error('Database not initialized. Call withDb() first.');
  return db;
};

export const withDb = async () => {
  if (isInitialized && db) return db;

  try {
    await fs.mkdir(DATA_DIR, { recursive: true });

    try {
      const data = await fs.readFile(DB_PATH, 'utf-8');
      db = JSON.parse(data);
      if (!db.users) db.users = [];
      if (!db.properties) db.properties = [];
      if (!db.tokens) db.tokens = [];
      if (!db.auditLog) db.auditLog = [];
      if (!db._meta) db._meta = defaultDb()._meta;
      db._meta.updatedAt = new Date().toISOString();
    } catch (error) {
      if (error.code === 'ENOENT') {
        db = defaultDb();
        await saveDb();
        console.log('📁 Created new database file');
      } else {
        throw error;
      }
    }

    isInitialized = true;
    return db;
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    throw error;
  }
};

const saveDb = async () => {
  if (!db) return;

  writeQueue = writeQueue.then(async () => {
    try {
      const backupPath = `${DB_PATH}.backup`;
      try {
        await fs.copyFile(DB_PATH, backupPath);
      } catch {
        // Ignore if original doesn't exist
      }

      db._meta.updatedAt = new Date().toISOString();
      await fs.writeFile(DB_PATH, JSON.stringify(db, null, 2));

      try {
        await fs.unlink(backupPath);
      } catch {
        // Ignore cleanup errors
      }
    } catch (error) {
      console.error('❌ Failed to save database:', error);
      throw error;
    }
  });

  await writeQueue;
};

export const save = saveDb;

// ===== Helpers =====
export const findUserByEmail = (email) => {
  return db?.users?.find(u => u.email.toLowerCase() === email.toLowerCase());
};

export const findUserById = (id) => {
  return db?.users?.find(u => u.id === id);
};

export const findPropertyById = (id) => {
  return db?.properties?.find(p => p.id === id);
};

export const findTokenByUserId = (userId, propertyId) => {
  return db?.tokens?.find(t => t.userId === userId && t.propertyId === propertyId);
};

export const generateId = () => {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
};

export const paginate = (array, page = 1, limit = 20) => {
  const start = (page - 1) * limit;
  const end = start + limit;
  return {
    data: array.slice(start, end),
    total: array.length,
    page: parseInt(page),
    limit: parseInt(limit),
    totalPages: Math.ceil(array.length / limit),
  };
};

export default {
  getDb,
  withDb,
  save,
  findUserByEmail,
  findUserById,
  findPropertyById,
  findTokenByUserId,
  generateId,
  paginate,
};