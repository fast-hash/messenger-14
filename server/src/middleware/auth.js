const jwt = require('jsonwebtoken');
const config = require('../config/env');
const User = require('../models/User');
const { toUserDto } = require('../services/userService');

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies && req.cookies.access_token;

    if (!token) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    let payload;
    try {
      payload = jwt.verify(token, config.jwtSecret);
    } catch (error) {
      return res.status(401).json({ error: 'Invalid or expired token', code: 'TOKEN_INVALID' });
    }

    const user = await User.findById(payload.id);
    if (!user) {
      return res.status(401).json({ error: 'Invalid or expired token', code: 'TOKEN_INVALID' });
    }

    if (user.accessDisabled) {
      return res.status(403).json({ error: 'Доступ ограничен администратором', code: 'ACCESS_DISABLED' });
    }

    const currentVersion = user.tokenVersion || 0;
    const tokenVersion = typeof payload.tokenVersion === 'number' ? payload.tokenVersion : 0;
    if (tokenVersion !== currentVersion) {
      return res.status(401).json({ error: 'Invalid or expired token', code: 'TOKEN_EXPIRED' });
    }

    req.user = toUserDto(user);

    return next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token', code: 'TOKEN_INVALID' });
  }
};

module.exports = authMiddleware;
