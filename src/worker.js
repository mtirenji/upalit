@"
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import { nanoid } from 'nanoid';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = new Hono();

// In-memory database (for Cloudflare Workers)
let db = {
  users: [],
  properties: [],
  tokens: [],
  auditLog: []
};

// ===== Helpers =====
const generateId = () => nanoid();
const findUserByEmail = (email) => db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
const findUserById = (id) => db.users.find(u => u.id === id);
const findPropertyById = (id) => db.properties.find(p => p.id === id);
const getSecret = (c, key) => c.env[key] || process.env[key];

// ===== Middleware =====
app.use('*', secureHeaders());
app.use('*', cors({
  origin: (origin) => {
    const allowed = [
      'http://localhost:3000',
      'http://localhost:5173',
      'https://upalit.pages.dev',
      'https://upalit.com'
    ];
    return allowed.includes(origin) ? origin : 'http://localhost:5173';
  },
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// ===== Auth Middleware =====
const authenticate = async (c, next) => {
  const authHeader = c.req.header('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Authentication required' }, 401);
  }
  
  const token = authHeader.slice(7);
  const secret = getSecret(c, 'JWT_ACCESS_SECRET');
  
  try {
    const decoded = jwt.verify(token, secret);
    const user = findUserById(decoded.id);
    
    if (!user || user.disabled) {
      return c.json({ error: 'Invalid or disabled account' }, 401);
    }
    
    c.set('user', user);
    await next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return c.json({ error: 'Access token expired' }, 401);
    }
    return c.json({ error: 'Invalid access token' }, 401);
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

// Health Check
app.get('/api/health', (c) => {
  return c.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: c.env.NODE_ENV || 'production',
    version: '1.0.0',
    users: db.users.length,
    properties: db.properties.length,
  });
});

// ===== AUTH ROUTES =====

// Register
app.post('/api/auth/register', async (c) => {
  try {
    const { email, password, fullName } = await c.req.json();

    if (!email || !password || !fullName) {
      return c.json({ error: 'Missing required fields: email, password, fullName' }, 400);
    }

    if (password.length < 8) {
      return c.json({ error: 'Password must be at least 8 characters' }, 400);
    }

    if (!email.includes('@')) {
      return c.json({ error: 'Invalid email format' }, 400);
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

    const accessSecret = getSecret(c, 'JWT_ACCESS_SECRET');
    const refreshSecret = getSecret(c, 'JWT_REFRESH_SECRET');
    
    const accessToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      accessSecret,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { id: user.id },
      refreshSecret,
      { expiresIn: '7d' }
    );

    const { password: _, ...userWithoutPassword } = user;
    return c.json({ 
      user: userWithoutPassword, 
      accessToken, 
      refreshToken 
    }, 201);
  } catch (error) {
    return c.json({ error: 'Registration failed: ' + error.message }, 500);
  }
});

// Login
app.post('/api/auth/login', async (c) => {
  try {
    const { email, password } = await c.req.json();

    if (!email || !password) {
      return c.json({ error: 'Email and password required' }, 400);
    }

    const user = findUserByEmail(email);
    if (!user) {
      return c.json({ error: 'Invalid credentials' }, 401);
    }

    if (user.disabled) {
      return c.json({ error: 'Account has been disabled' }, 403);
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return c.json({ error: 'Invalid credentials' }, 401);
    }

    const accessSecret = getSecret(c, 'JWT_ACCESS_SECRET');
    const refreshSecret = getSecret(c, 'JWT_REFRESH_SECRET');
    
    const accessToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      accessSecret,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { id: user.id },
      refreshSecret,
      { expiresIn: '7d' }
    );

    const { password: _, ...userWithoutPassword } = user;
    return c.json({ 
      user: userWithoutPassword, 
      accessToken, 
      refreshToken 
    });
  } catch (error) {
    return c.json({ error: 'Login failed: ' + error.message }, 500);
  }
});

// Refresh Token
app.post('/api/auth/refresh', async (c) => {
  try {
    const { refreshToken } = await c.req.json();

    if (!refreshToken) {
      return c.json({ error: 'Refresh token required' }, 400);
    }

    const refreshSecret = getSecret(c, 'JWT_REFRESH_SECRET');
    const decoded = jwt.verify(refreshToken, refreshSecret);
    const user = findUserById(decoded.id);

    if (!user || user.disabled) {
      return c.json({ error: 'Invalid refresh token' }, 401);
    }

    const accessSecret = getSecret(c, 'JWT_ACCESS_SECRET');
    const accessToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      accessSecret,
      { expiresIn: '15m' }
    );

    return c.json({ accessToken });
  } catch (error) {
    return c.json({ error: 'Invalid refresh token' }, 401);
  }
});

// Get Current User
app.get('/api/auth/me', authenticate, (c) => {
  const user = c.get('user');
  const { password, ...userWithoutPassword } = user;
  return c.json({ user: userWithoutPassword });
});

// ===== ADMIN ROUTES =====

// List Users
app.get('/api/admin/users', authenticate, requireAdmin, (c) => {
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
    totalPages: Math.ceil(users.length / parseInt(limit))
  });
});

// Get Single User
app.get('/api/admin/users/:id', authenticate, requireAdmin, (c) => {
  const { id } = c.req.param();
  const user = findUserById(id);
  
  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }
  
  const { password, ...userWithoutPassword } = user;
  return c.json({ user: userWithoutPassword });
});

// Update KYC Status
app.patch('/api/admin/users/:id/kyc', authenticate, requireAdmin, async (c) => {
  const { id } = c.req.param();
  const { status, reason } = await c.req.json();

  if (!['pending', 'verified', 'rejected'].includes(status)) {
    return c.json({ error: 'Invalid KYC status' }, 400);
  }

  const user = findUserById(id);
  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }

  const oldStatus = user.kycStatus;
  user.kycStatus = status;
  user.updatedAt = new Date().toISOString();

  // Audit log
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

  return c.json({ 
    message: 'KYC status updated', 
    user: { id: user.id, email: user.email, kycStatus: user.kycStatus } 
  });
});

// Update Role
app.patch('/api/admin/users/:id/role', authenticate, requireAdmin, async (c) => {
  const { id } = c.req.param();
  const { role } = await c.req.json();

  if (!['investor', 'admin'].includes(role)) {
    return c.json({ error: 'Invalid role' }, 400);
  }

  const currentUser = c.get('user');
  if (id === currentUser.id) {
    return c.json({ error: 'Cannot change your own role' }, 403);
  }

  const user = findUserById(id);
  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }

  const oldRole = user.role;
  user.role = role;
  user.updatedAt = new Date().toISOString();

  db.auditLog.push({
    id: generateId(),
    userId: currentUser.id,
    action: 'role_update',
    targetUserId: id,
    oldValue: oldRole,
    newValue: role,
    timestamp: new Date().toISOString(),
  });

  return c.json({ 
    message: 'Role updated', 
    user: { id: user.id, email: user.email, role: user.role } 
  });
});

// Disable/Enable User
app.patch('/api/admin/users/:id/disable', authenticate, requireAdmin, async (c) => {
  const { id } = c.req.param();
  const { disabled } = await c.req.json();

  if (typeof disabled !== 'boolean') {
    return c.json({ error: 'Disabled must be a boolean' }, 400);
  }

  const currentUser = c.get('user');
  if (id === currentUser.id) {
    return c.json({ error: 'Cannot disable your own account' }, 403);
  }

  const user = findUserById(id);
  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }

  user.disabled = disabled;
  user.updatedAt = new Date().toISOString();

  db.auditLog.push({
    id: generateId(),
    userId: currentUser.id,
    action: disabled ? 'user_disabled' : 'user_enabled',
    targetUserId: id,
    timestamp: new Date().toISOString(),
  });

  return c.json({ 
    message: disabled ? 'User disabled' : 'User enabled',
    user: { id: user.id, disabled: user.disabled } 
  });
});

// Get Properties
app.get('/api/admin/properties', authenticate, requireAdmin, (c) => {
  const { status, q, page = 1, limit = 50 } = c.req.query();

  let properties = [...db.properties];
  if (status) properties = properties.filter(p => p.status === status);
  if (q) {
    const search = q.toLowerCase();
    properties = properties.filter(p => 
      p.name.toLowerCase().includes(search) || 
      p.location.toLowerCase().includes(search)
    );
  }

  properties.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const start = (parseInt(page) - 1) * parseInt(limit);
  const end = start + parseInt(limit);
  const paginated = properties.slice(start, end);

  return c.json({
    data: paginated,
    total: properties.length,
    page: parseInt(page),
    limit: parseInt(limit),
    totalPages: Math.ceil(properties.length / parseInt(limit))
  });
});

// Create Property
app.post('/api/admin/properties', authenticate, requireAdmin, async (c) => {
  const { name, location, description, price, tokenPrice, totalTokens, status = 'draft' } = await c.req.json();

  if (!name || !location || !price) {
    return c.json({ error: 'Name, location, and price are required' }, 400);
  }

  if (typeof price !== 'number' || price <= 0) {
    return c.json({ error: 'Price must be a positive number' }, 400);
  }

  const property = {
    id: generateId(),
    name: name.trim(),
    location: location.trim(),
    description: description?.trim() || '',
    price: parseFloat(price),
    tokenPrice: parseFloat(tokenPrice) || parseFloat(price) / 1000,
    totalTokens: parseInt(totalTokens) || 10000,
    tokensSold: 0,
    status: ['draft', 'active', 'funded', 'sold'].includes(status) ? status : 'draft',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastAppraisal: new Date().toISOString(),
    createdBy: c.get('user').id,
  };

  db.properties.push(property);

  db.auditLog.push({
    id: generateId(),
    userId: c.get('user').id,
    action: 'property_created',
    targetPropertyId: property.id,
    details: { name: property.name, location: property.location, price: property.price },
    timestamp: new Date().toISOString(),
  });

  return c.json({ message: 'Property created successfully', property }, 201);
});

// Update Property
app.patch('/api/admin/properties/:id', authenticate, requireAdmin, async (c) => {
  const { id } = c.req.param();
  const updates = await c.req.json();

  const property = findPropertyById(id);
  if (!property) {
    return c.json({ error: 'Property not found' }, 404);
  }

  const oldValues = { ...property };
  const allowedUpdates = ['name', 'location', 'description', 'price', 'tokenPrice', 'totalTokens', 'status', 'lastAppraisal'];

  for (const key of allowedUpdates) {
    if (updates[key] !== undefined) {
      if (key === 'price' || key === 'tokenPrice') {
        property[key] = parseFloat(updates[key]);
      } else if (key === 'totalTokens') {
        property[key] = parseInt(updates[key]);
      } else {
        property[key] = updates[key];
      }
    }
  }

  property.updatedAt = new Date().toISOString();

  db.auditLog.push({
    id: generateId(),
    userId: c.get('user').id,
    action: 'property_updated',
    targetPropertyId: id,
    details: {
      before: { name: oldValues.name, price: oldValues.price, status: oldValues.status },
      after: { name: property.name, price: property.price, status: property.status }
    },
    timestamp: new Date().toISOString(),
  });

  return c.json({ message: 'Property updated successfully', property });
});

// Delete Property
app.delete('/api/admin/properties/:id', authenticate, requireAdmin, (c) => {
  const { id } = c.req.param();
  
  const property = findPropertyById(id);
  if (!property) {
    return c.json({ error: 'Property not found' }, 404);
  }

  if (property.status !== 'draft') {
    return c.json({ error: 'Only draft properties can be deleted' }, 403);
  }

  db.properties = db.properties.filter(p => p.id !== id);

  db.auditLog.push({
    id: generateId(),
    userId: c.get('user').id,
    action: 'property_deleted',
    targetPropertyId: id,
    details: { name: property.name },
    timestamp: new Date().toISOString(),
  });

  return c.json({ message: 'Property deleted successfully' });
});

// Get Stats
app.get('/api/admin/stats', authenticate, requireAdmin, (c) => {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  return c.json({
    users: {
      total: db.users.length,
      verified: db.users.filter(u => u.kycStatus === 'verified').length,
      pending: db.users.filter(u => u.kycStatus === 'pending').length,
      rejected: db.users.filter(u => u.kycStatus === 'rejected').length,
      admins: db.users.filter(u => u.role === 'admin').length,
      newLast30Days: db.users.filter(u => new Date(u.createdAt) > thirtyDaysAgo).length,
    },
    properties: {
      total: db.properties.length,
      active: db.properties.filter(p => p.status === 'active').length,
      funded: db.properties.filter(p => p.status === 'funded').length,
      sold: db.properties.filter(p => p.status === 'sold').length,
      draft: db.properties.filter(p => p.status === 'draft').length,
    },
    tokens: {
      totalSold: db.properties.reduce((sum, p) => sum + p.tokensSold, 0),
      totalValueLocked: db.properties
        .filter(p => ['active', 'funded'].includes(p.status))
        .reduce((sum, p) => sum + (p.tokenPrice * p.tokensSold), 0),
    },
    audit: {
      totalEntries: db.auditLog.length,
      last30Days: db.auditLog.filter(a => new Date(a.timestamp) > thirtyDaysAgo).length,
    },
    timestamp: new Date().toISOString(),
  });
});

// Get Audit Log
app.get('/api/admin/audit-log', authenticate, requireAdmin, (c) => {
  const { action, userId, page = 1, limit = 50 } = c.req.query();

  let logs = [...db.auditLog];
  if (action) logs = logs.filter(l => l.action === action);
  if (userId) logs = logs.filter(l => l.userId === userId || l.targetUserId === userId);

  logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  const start = (parseInt(page) - 1) * parseInt(limit);
  const end = start + parseInt(limit);
  const paginated = logs.slice(start, end);

  // Enrich with user names
  const enriched = paginated.map(log => {
    const actor = db.users.find(u => u.id === log.userId);
    const target = db.users.find(u => u.id === log.targetUserId);
    return {
      ...log,
      actorName: actor?.fullName || 'Unknown',
      actorEmail: actor?.email || 'Unknown',
      targetName: target?.fullName || 'Unknown',
      targetEmail: target?.email || 'Unknown',
    };
  });

  return c.json({
    data: enriched,
    total: logs.length,
    page: parseInt(page),
    limit: parseInt(limit),
    totalPages: Math.ceil(logs.length / parseInt(limit))
  });
});

// ===== Seed Sample Data =====
app.post('/api/admin/seed', authenticate, requireAdmin, async (c) => {
  // Add sample properties if none exist
  if (db.properties.length === 0) {
    const sampleProperties = [
      {
        name: 'Marina Court, Unit 14B',
        location: 'Dubai Marina',
        description: 'Luxury 2-bedroom apartment with panoramic sea views.',
        price: 2150000,
        tokenPrice: 215,
        totalTokens: 10000,
        tokensSold: 6200,
        status: 'active',
        lastAppraisal: '2026-05-15T00:00:00.000Z',
      },
      {
        name: 'Circle Residence, 3-Bed Villa',
        location: 'Jumeirah Village Circle',
        description: 'Spacious 3-bedroom villa with private garden and pool.',
        price: 2740500,
        tokenPrice: 189,
        totalTokens: 14500,
        tokensSold: 5945,
        status: 'active',
        lastAppraisal: '2026-04-20T00:00:00.000Z',
      },
      {
        name: 'Bay Terraces, Unit 9C',
        location: 'Business Bay',
        description: 'Modern 1-bedroom apartment in the heart of Dubai\'s business district.',
        price: 1976200,
        tokenPrice: 241,
        totalTokens: 8200,
        tokensSold: 7216,
        status: 'active',
        lastAppraisal: '2026-06-01T00:00:00.000Z',
      },
    ];

    for (const propData of sampleProperties) {
      db.properties.push({
        id: generateId(),
        ...propData,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        createdBy: c.get('user').id,
      });
    }

    return c.json({ 
      message: 'Sample data seeded successfully', 
      count: sampleProperties.length 
    });
  }

  return c.json({ message: 'Sample data already exists', count: db.properties.length });
});

// ===== Error Handler =====
app.onError((err, c) => {
  console.error('Error:', err);
  return c.json({ 
    error: 'Internal server error',
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  }, 500);
});

// ===== 404 Handler =====
app.notFound((c) => {
  return c.json({ error: 'Route not found' }, 404);
});

export default {
  fetch: app.fetch,
};
"@ | Out-File -FilePath src\worker.js -Encoding utf8