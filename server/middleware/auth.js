/**
 * @fileoverview Authentication middleware for JWT-based auth.
 * @module middleware/auth
 */

import jwt from 'jsonwebtoken';

/**
 * JWT_SECRET — must be set via environment variable in production.
 * In development, falls back to a demo secret with a loud warning.
 */
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = (() => {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  if (NODE_ENV === 'production') {
    throw new Error('FATAL: JWT_SECRET environment variable is required in production. Set it in your deployment config (Render, Vercel, etc.).');
  }
  console.warn('⚠️  WARNING: JWT_SECRET not set — using insecure dev-only fallback. DO NOT deploy like this!');
  return 'sehat-saathi-dev-secret-UNSAFE';
})();

/** @constant {string} TOKEN_EXPIRY - JWT token expiration duration */
const TOKEN_EXPIRY = '7d';

/**
 * Generates a signed JWT token for the given payload.
 *
 * @param {Object} payload - Data to encode (userId, role, refId, phone)
 * @returns {string} Signed JWT string
 */
export function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
}

/**
 * Verifies and decodes a JWT token.
 *
 * @param {string} token - JWT string to verify
 * @returns {Object} Decoded payload
 * @throws {jwt.JsonWebTokenError} If token is invalid
 * @throws {jwt.TokenExpiredError} If token has expired
 */
export function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

/**
 * Express middleware that validates the Authorization header.
 * Attaches decoded user data to `req.user` on success.
 *
 * Expected header format: `Authorization: Bearer <token>`
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. No token provided.' });
  }

  try {
    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    const message = err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
    return res.status(401).json({ error: message });
  }
}

/**
 * Express middleware factory for role-based access control (RBAC).
 * Must be used AFTER authMiddleware.
 *
 * @param {...string} roles - Allowed roles (e.g., 'doctor', 'patient', 'pharmacist')
 * @returns {Function} Express middleware
 *
 * @example
 * router.get('/admin', authMiddleware, roleGuard('doctor'), handler);
 */
export function roleGuard(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}
