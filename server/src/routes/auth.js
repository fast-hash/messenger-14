const express = require('express');
const jwt = require('jsonwebtoken');
const config = require('../config/env');
const authMiddleware = require('../middleware/auth');
const asyncHandler = require('../utils/asyncHandler');
const userService = require('../services/userService');
const registrationService = require('../services/registrationService');

const router = express.Router();

const setAuthCookie = (res, payload) => {
  const tokenPayload = { ...payload, tokenVersion: payload.tokenVersion || 0 };
  const token = jwt.sign(tokenPayload, config.jwtSecret, { expiresIn: '7d' });
  res.cookie('access_token', token, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
};

router.post(
  '/register',
  asyncHandler(async (req, res) => {
    await registrationService.createRegistrationRequest(req.body || {});
    res.status(201).json({ message: 'Заявка отправлена администратору' });
  })
);

router.post(
  '/login',
  asyncHandler(async (req, res) => {
    const user = await userService.authenticateUser(req.body || {});
    setAuthCookie(res, { ...user, tokenVersion: user.tokenVersion || 0 });
    res.json({ user });
  })
);

router.post('/logout', (req, res) => {
  res.clearCookie('access_token');
  res.status(204).send();
});

router.get(
  '/me',
  authMiddleware,
  asyncHandler(async (req, res) => {
    res.json({ user: req.user });
  })
);

module.exports = router;
