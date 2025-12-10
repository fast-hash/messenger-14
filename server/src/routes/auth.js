const express = require('express');
const authMiddleware = require('../middleware/auth');
const asyncHandler = require('../utils/asyncHandler');
const userService = require('../services/userService');
const registrationService = require('../services/registrationService');
const { registerOrUpdateDevice, toDeviceDto } = require('../services/deviceService');
const { setAuthCookie } = require('../utils/authCookie');
const { getRequestIp } = require('../utils/requestIp');
const { logEvent } = require('../services/auditLogService');
const Device = require('../models/Device');
const User = require('../models/User');

const router = express.Router();

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
    const { device } = req.body || {};
    const user = await userService.authenticateUser(req.body || {});
    const userRecord = await User.findById(user.id);

    if (!userRecord) {
      const error = new Error('Invalid credentials');
      error.status = 401;
      throw error;
    }

    const ipAddress = getRequestIp(req);
    const existingDevicesCount = await Device.countDocuments({ userId: userRecord._id });
    const shouldForceTrust = Boolean(userRecord.forceTrustNextDevice);
    const trustOnCreate = shouldForceTrust || existingDevicesCount === 0;

    const deviceRecord = await registerOrUpdateDevice({
      userId: user.id,
      device,
      ipAddress,
      trustOnCreate,
      forceTrust: shouldForceTrust,
    });

    if (shouldForceTrust && userRecord.forceTrustNextDevice) {
      userRecord.forceTrustNextDevice = false;
      await userRecord.save();
    }

    setAuthCookie(res, {
      ...user,
      tokenVersion: user.tokenVersion || 0,
      deviceId: deviceRecord.deviceId,
      deviceTokenVersion: deviceRecord.tokenVersion || 0,
    });

    await logEvent({
      actorId: user.id,
      event: 'auth_login',
      ip: ipAddress || null,
      deviceInfo: { name: deviceRecord.name, platform: deviceRecord.platform, id: deviceRecord.deviceId },
    });

    res.json({ user, device: toDeviceDto(deviceRecord) });
  })
);

router.post(
  '/logout',
  authMiddleware,
  asyncHandler(async (req, res) => {
    res.clearCookie('access_token');

    await logEvent({
      actorId: req.user.id,
      event: 'auth_logout',
      ip: getRequestIp(req) || null,
      deviceInfo: req.device
        ? { name: req.device.name, platform: req.device.platform, id: req.device.deviceId }
        : null,
    });

    res.status(204).send();
  })
);

router.get(
  '/me',
  authMiddleware,
  asyncHandler(async (req, res) => {
    res.json({ user: req.user, device: toDeviceDto(req.device) });
  })
);

module.exports = router;
