const mongoose = require('mongoose');

const auditEventSchema = new mongoose.Schema(
  {
    actorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    event: {
      type: String,
      enum: [
        'auth_login',
        'auth_logout',
        'device_new',
        'device_revoked',
        'device_trusted',
        'device_trust_reset',
      ],
      required: true,
    },
    ip: {
      type: String,
      default: null,
    },
    deviceInfo: {
      type: Object,
      default: null,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { versionKey: false, collection: 'audit_events' }
);

auditEventSchema.set('toJSON', {
  transform: (_, ret) => {
    ret.id = ret._id.toString();
    delete ret._id;
    return ret;
  },
});

module.exports = mongoose.model('AuditEvent', auditEventSchema);
