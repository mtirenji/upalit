import express from 'express';
import { authenticate, requireAdmin } from './auth.js';
import { getDb, save, findUserById, findPropertyById, generateId, paginate } from '../db.js';

const router = express.Router();

router.use(authenticate);
router.use(requireAdmin);

// ===== USERS =====
router.get('/users', async (req, res) => {
  const { kycStatus, q, role, page = 1, limit = 50 } = req.query;
  const db = getDb();

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
  users = users.map(u => { const { password, ...rest } = u; return rest; });

  res.json(paginate(users, parseInt(page), parseInt(limit)));
});

router.get('/users/:id', async (req, res) => {
  const user = findUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password, ...rest } = user;
  res.json({ user: rest });
});

router.patch('/users/:id/kyc', async (req, res) => {
  const { status, reason } = req.body;
  if (!['pending', 'verified', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Invalid KYC status' });
  }

  const user = findUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const db = getDb();
  const oldStatus = user.kycStatus;
  user.kycStatus = status;
  user.updatedAt = new Date().toISOString();

  db.auditLog.push({
    id: generateId(),
    userId: req.user.id,
    action: 'kyc_update',
    targetUserId: req.params.id,
    oldValue: oldStatus,
    newValue: status,
    reason: reason || 'Admin action',
    timestamp: new Date().toISOString(),
  });

  await save();
  res.json({ message: 'KYC status updated', user: { id: user.id, email: user.email, kycStatus: user.kycStatus } });
});

router.patch('/users/:id/role', async (req, res) => {
  const { role } = req.body;
  if (!['investor', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  if (req.params.id === req.user.id) {
    return res.status(403).json({ error: 'Cannot change your own role' });
  }

  const user = findUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const db = getDb();
  const oldRole = user.role;
  user.role = role;
  user.updatedAt = new Date().toISOString();

  db.auditLog.push({
    id: generateId(),
    userId: req.user.id,
    action: 'role_update',
    targetUserId: req.params.id,
    oldValue: oldRole,
    newValue: role,
    timestamp: new Date().toISOString(),
  });

  await save();
  res.json({ message: 'Role updated', user: { id: user.id, email: user.email, role: user.role } });
});

router.patch('/users/:id/disable', async (req, res) => {
  const { disabled } = req.body;
  if (typeof disabled !== 'boolean') {
    return res.status(400).json({ error: 'Disabled must be a boolean' });
  }
  if (req.params.id === req.user.id) {
    return res.status(403).json({ error: 'Cannot disable your own account' });
  }

  const user = findUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const db = getDb();
  user.disabled = disabled;
  user.updatedAt = new Date().toISOString();

  db.auditLog.push({
    id: generateId(),
    userId: req.user.id,
    action: disabled ? 'user_disabled' : 'user_enabled',
    targetUserId: req.params.id,
    timestamp: new Date().toISOString(),
  });

  await save();
  res.json({ message: disabled ? 'User disabled' : 'User enabled', user: { id: user.id, disabled: user.disabled } });
});

// ===== PROPERTIES =====
router.get('/properties', async (req, res) => {
  const { status, q, page = 1, limit = 50 } = req.query;
  const db = getDb();

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
  res.json(paginate(properties, parseInt(page), parseInt(limit)));
});

router.get('/properties/:id', async (req, res) => {
  const property = findPropertyById(req.params.id);
  if (!property) return res.status(404).json({ error: 'Property not found' });
  res.json({ property });
});

router.post('/properties', async (req, res) => {
  const { name, location, description, price, tokenPrice, totalTokens, status = 'draft' } = req.body;

  if (!name || !location || !price) {
    return res.status(400).json({ error: 'Name, location, and price are required' });
  }
  if (typeof price !== 'number' || price <= 0) {
    return res.status(400).json({ error: 'Price must be a positive number' });
  }

  const db = getDb();
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
    createdBy: req.user.id,
  };

  db.properties.push(property);
  db.auditLog.push({
    id: generateId(),
    userId: req.user.id,
    action: 'property_created',
    targetPropertyId: property.id,
    details: { name: property.name, location: property.location, price: property.price },
    timestamp: new Date().toISOString(),
  });

  await save();
  res.status(201).json({ message: 'Property created successfully', property });
});

router.patch('/properties/:id', async (req, res) => {
  const property = findPropertyById(req.params.id);
  if (!property) return res.status(404).json({ error: 'Property not found' });

  const db = getDb();
  const oldValues = { ...property };
  const allowedUpdates = ['name', 'location', 'description', 'price', 'tokenPrice', 'totalTokens', 'status', 'lastAppraisal'];

  for (const key of allowedUpdates) {
    if (req.body[key] !== undefined) {
      if (key === 'price' || key === 'tokenPrice') {
        property[key] = parseFloat(req.body[key]);
      } else if (key === 'totalTokens') {
        property[key] = parseInt(req.body[key]);
      } else {
        property[key] = req.body[key];
      }
    }
  }

  if (req.body.tokensSold !== undefined) {
    return res.status(403).json({ error: 'tokensSold cannot be updated directly' });
  }

  property.updatedAt = new Date().toISOString();

  db.auditLog.push({
    id: generateId(),
    userId: req.user.id,
    action: 'property_updated',
    targetPropertyId: req.params.id,
    details: { before: { name: oldValues.name, price: oldValues.price, status: oldValues.status }, after: { name: property.name, price: property.price, status: property.status } },
    timestamp: new Date().toISOString(),
  });

  await save();
  res.json({ message: 'Property updated successfully', property });
});

router.delete('/properties/:id', async (req, res) => {
  const property = findPropertyById(req.params.id);
  if (!property) return res.status(404).json({ error: 'Property not found' });
  if (property.status !== 'draft') {
    return res.status(403).json({ error: 'Only draft properties can be deleted' });
  }

  const db = getDb();
  db.properties = db.properties.filter(p => p.id !== req.params.id);

  db.auditLog.push({
    id: generateId(),
    userId: req.user.id,
    action: 'property_deleted',
    targetPropertyId: req.params.id,
    details: { name: property.name },
    timestamp: new Date().toISOString(),
  });

  await save();
  res.json({ message: 'Property deleted successfully' });
});

// ===== STATS =====
router.get('/stats', async (req, res) => {
  const db = getDb();
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  res.json({
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
      totalValueLocked: db.properties.filter(p => ['active', 'funded'].includes(p.status)).reduce((sum, p) => sum + (p.tokenPrice * p.tokensSold), 0),
      totalPropertyValue: db.properties.filter(p => ['active', 'funded'].includes(p.status)).reduce((sum, p) => sum + p.price, 0),
    },
    audit: {
      totalEntries: db.auditLog.length,
      last30Days: db.auditLog.filter(a => new Date(a.timestamp) > thirtyDaysAgo).length,
    },
    timestamp: new Date().toISOString(),
  });
});

// ===== AUDIT LOG =====
router.get('/audit-log', async (req, res) => {
  const { action, userId, page = 1, limit = 50 } = req.query;
  const db = getDb();

  let logs = [...db.auditLog];
  if (action) logs = logs.filter(l => l.action === action);
  if (userId) logs = logs.filter(l => l.userId === userId || l.targetUserId === userId);

  logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const result = paginate(logs, parseInt(page), parseInt(limit));

  const enriched = result.data.map(log => {
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

  res.json({ ...result, data: enriched });
});

export default router;