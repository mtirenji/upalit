import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { getDb, save, findUserByEmail, findUserById, generateId } from '../db.js';

const router = express.Router();

// ===== Rate Limiters =====
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX) || 20,
  message: { error: 'Too many authentication attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ===== Validation =====
const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const validatePassword = (password) => password && password.length >= 8;

// ===== Register =====
router.post('/register', authLimiter, async (req, res) => {
  const { email, password, fullName } = req.body;

  if (!email || !password || !fullName) {
    return res.status(400).json({ error: 'Missing required fields: email, password, fullName' });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  if (fullName.length < 2) {
    return res.status(400).json({ error: 'Full name must be at least 2 characters' });
  }

  const db = getDb();

  if (findUserByEmail(email)) {
    return res.status(409).json({ error: 'Email already registered' });
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
  await save();

  const accessToken = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m' }
  );

  const refreshToken = jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRY || '7d' }
  );

  const { password: _, ...userWithoutPassword } = user;

  res.status(201).json({
    user: userWithoutPassword,
    accessToken,
    refreshToken,
  });
});

// ===== Login =====
router.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const user = findUserByEmail(email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (user.disabled) {
    return res.status(403).json({ error: 'Account has been disabled' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const accessToken = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m' }
  );

  const refreshToken = jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRY || '7d' }
  );

  const { password: _, ...userWithoutPassword } = user;

  res.json({
    user: userWithoutPassword,
    accessToken,
    refreshToken,
  });
});

// ===== Refresh Token =====
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = findUserById(decoded.id);

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (user.disabled) {
      return res.status(403).json({ error: 'Account disabled' });
    }

    const accessToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m' }
    );

    res.json({ accessToken });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Refresh token expired' });
    }
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// ===== Logout =====
router.post('/logout', (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// ===== Get Current User =====
router.get('/me', authenticate, (req, res) => {
  const { password, ...userWithoutPassword } = req.user;
  res.json({ user: userWithoutPassword });
});

// ===== Authentication Middleware =====
export const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    const user = findUserById(decoded.id);

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (user.disabled) {
      return res.status(403).json({ error: 'Account disabled' });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Access token expired' });
    }
    res.status(401).json({ error: 'Invalid access token' });
  }
};

// ===== Admin Middleware =====
export const requireAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

export default router;