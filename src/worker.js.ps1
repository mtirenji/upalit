@"
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import { nanoid } from 'nanoid';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = new Hono();

// ===== Database (using R2 or KV) =====
let db = null;

const getDb = async (env) => {
  if (db) return db;
  
  try {
    const data = await env.DATA_BUCKET.get('db.json');
    if (data) {
      db = JSON.parse(await data.text());
    } else {
      db = { users: [], properties: [], tokens: [], auditLog: [] };
      await saveDb(env);
    }
    return db;
  } catch {
    db = { users: [], properties: [], tokens: [], auditLog: [] };
    await saveDb(env);
    return db;
  }
};

const saveDb = async (env) => {
  if (!db) return;
  await env.DATA_BUCKET.put('db.json', JSON.stringify(db, null, 2));
};

// ===== Helpers =====
const generateId = () => nanoid();
const findUserByEmail = (email) => db?.users?.find(u => u.email.toLowerCase() === email.toLowerCase());
const findUserById = (id) => db?.users?.find(u => u.id === id);
const findPropertyById = (id) => db?.properties?.find(p => p.id === id);

// ===== Middleware =====
app.use('*', secureHeaders());
app.use('*', cors({
  origin: (origin) => {
    const allowed = ['http://localhost:3000', 'http://localhost:5173'];
    return allowed.includes(origin) ? origin : 'http://localhost:5173';
  },
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

// ===== Auth Middleware =====
const authenticate = async (c, next) => {
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Authentication required' }, 401);
  }
  
  const token = authHeader.slice(7);
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET || c.env.JWT_ACCESS_SECRET);
    const env = c.env;
    db = await getDb(env);
    const user = findUserById(decoded.id);
    
    if (!user || user.disabled) {
      return c.json({ error: 'Invalid or disabled account' }, 401);
    }
    
    c.set('user', user);
    await next();
  } catch (error) {
    return c.json({ error: 'Invalid or expired token' }, 401);
  }
};

const requireAdmin = async (c, next) => {
  const user = c.get('user');
  if (!user || user.role !== 'admin') {
    return c.json({ error: 'Admin access required' }, 403);
  }
  await next();
};

// ===== Routes =====
app.get('/api/health', async (c) => {
  const env = c.env;
  db = await getDb(env);
  return c.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: c.env.NODE_ENV || 'production',
    userCount: db?.users?.length || 0,
  });
});

// Auth routes
app.post('/api/auth/register', async (c) => {
  const { email, password, fullName } = await c.req.json();
  const env = c.env;
  db = await getDb(env);

  if (!email || !password || !fullName) {
    return c.json({ error: 'Missing required fields' }, 400);
  }

  if (password.length < 8) {
    return c.json({ error: 'Password must be at least 8 characters' }, 400);
  }

  if (findUserByEmail(email)) {
    return c.json({ error: 'Email already registered' }, 409);
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const user = {
    id: generateId(),
    email: email.toLowerCase(),
    fullName: fullName.trim(),
    password: hashedPassword,
    role: 'investor',
    kycStatus: 'pending',
    disabled: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  db.users.push(user);
  await saveDb(env);

  const accessToken = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_ACCESS_SECRET || c.env.JWT_ACCESS_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET || c.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  const { password: _, ...userWithoutPassword } = user;
  return c.json({ user: userWithoutPassword, accessToken, refreshToken }, 201);
});

app.post('/api/auth/login', async (c) => {
  const { email, password } = await c.req.json();
  const env = c.env;
  db = await getDb(env);

  if (!email || !password) {
    return c.json({ error: 'Email and password required' }, 400);
  }

  const user = findUserByEmail(email);
  if (!user || user.disabled) {
    return c.json({ error: 'Invalid credentials' }, 401);
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return c.json({ error: 'Invalid credentials' }, 401);
  }

  const accessToken = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_ACCESS_SECRET || c.env.JWT_ACCESS_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET || c.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  const { password: _, ...userWithoutPassword } = user;
  return c.json({ user: userWithoutPassword, accessToken, refreshToken });
});

app.post('/api/auth/refresh', async (c) => {
  const { refreshToken } = await c.req.json();
  const env = c.env;
  db = await getDb(env);

  if (!refreshToken) {
    return c.json({ error: 'Refresh token required' }, 400);
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || c.env.JWT_REFRESH_SECRET);
    const user = findUserById(decoded.id);

    if (!user || user.disabled) {
      return c.json({ error: 'Invalid refresh token' }, 401);
    }

    const accessToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_ACCESS_SECRET || c.env.JWT_ACCESS_SECRET,
      { expiresIn: '15m' }
    );

    return c.json({ accessToken });
  } catch {
    return c.json({ error: 'Invalid refresh token' }, 401);
  }
});

app.get('/api/auth/me', authenticate, (c) => {
  const user = c.get('user');
  const { password, ...userWithoutPassword } = user;
  return c.json({ user: userWithoutPassword });
});

// Admin routes
app.get('/api/admin/users', authenticate, requireAdmin, async (c) => {
  const env = c.env;
  db = await getDb(env);
  const { q, role, kycStatus, page = 1, limit = 50 } = c.req.query();

  let users = [...db.users];
  if (kycStatus) users = users.filter(u => u.kycStatus === kycStatus);
  if (role) users = users.filter(u => u.role === role);
  if (q) {
    const search = q.toLowerCase();
    users = users.filter(u => 
      u.email.toLowerCase().includes(search) || 
      u.fullName.toLowerCase().includes(search)
    );
  }

  users.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const start = (parseInt(page) - 1) * parseInt(limit);
  const end = start + parseInt(limit);
  const paginated = users.slice(start, end).map(({ password, ...rest }) => rest);

  return c.json({
    data: paginated,
    total: users.length,
    page: parseInt(page),
    limit: parseInt(limit),
  });
});

app.patch('/api/admin/users/:id/kyc', authenticate, requireAdmin, async (c) => {
  const { id } = c.req.param();
  const { status, reason } = await c.req.json();
  const env = c.env;
  db = await getDb(env);

  if (!['pending', 'verified', 'rejected'].includes(status)) {
    return c.json({ error: 'Invalid KYC status' }, 400);
  }

  const user = findUserById(id);
  if (!user) return c.json({ error: 'User not found' }, 404);

  const oldStatus = user.kycStatus;
  user.kycStatus = status;
  user.updatedAt = new Date().toISOString();

  db.auditLog.push({
    id: generateId(),
    userId: c.get('user').id,
    action: 'kyc_update',
    targetUserId: id,
    oldValue: oldStatus,
    newValue: status,
    reason: reason || 'Admin action',
    timestamp: new Date().toISOString(),
  });

  await saveDb(env);
  return c.json({ message: 'KYC status updated', user: { id: user.id, email: user.email, kycStatus: user.kycStatus } });
});

app.get('/api/admin/stats', authenticate, requireAdmin, async (c) => {
  const env = c.env;
  db = await getDb(env);

  return c.json({
    users: {
      total: db.users.length,
      verified: db.users.filter(u => u.kycStatus === 'verified').length,
      pending: db.users.filter(u => u.kycStatus === 'pending').length,
      rejected: db.users.filter(u => u.kycStatus === 'rejected').length,
      admins: db.users.filter(u => u.role === 'admin').length,
    },
    properties: {
      total: db.properties.length,
      active: db.properties.filter(p => p.status === 'active').length,
      funded: db.properties.filter(p => p.status === 'funded').length,
      sold: db.properties.filter(p => p.status === 'sold').length,
      draft: db.properties.filter(p => p.status === 'draft').length,
    },
    timestamp: new Date().toISOString(),
  });
});

export default {
  fetch: app.fetch,
};
"@ | Out-File -FilePath src\worker.js -Encoding utf8