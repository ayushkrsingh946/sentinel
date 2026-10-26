/**
 * Sentinel Guard Middleware for Node.js / Express
 * Real-time request inspection with fast regex heuristics and monitor-only default mode.
 */

const fs = require('fs');
const path = require('path');

const FAST_RULES = [
  { name: 'path_traversal', regex: /(\.\.\/|\.\.\\|etc\/(passwd|shadow)|windows\/win\.ini)/i, weight: 35 },
  { name: 'sql_injection', regex: /(union\s+select|select\s+.*\s+from|'\s+or\s+['0-9]+=['0-9]+|;\s*drop\s+table)/i, weight: 40 },
  { name: 'cmd_injection', regex: /(\||;|`|\$\()\s*(cat|ls|whoami|curl|wget|id|nc|bash|sh)\b/i, weight: 45 },
  { name: 'xss_injection', regex: /(<script\b|javascript:|onerror\s*=|onload\s*=|alert\s*\()/i, weight: 30 },
  { name: 'scanner_fingerprint', regex: /(sqlmap|nikto|nuclei|acunetix|masscan)/i, weight: 30 }
];

class SentinelExpressGuard {
  constructor(options = {}) {
    this.mode = (options.mode || 'monitor').toLowerCase(); // 'monitor' | 'block'
    this.blockThreshold = options.blockThreshold || 70;
    this.allowlist = new Set(options.allowlist || ['127.0.0.1', '::1', 'localhost']);
    this.blocks = new Map(); // ip -> { reason, expiresAt }
    this.defaultTtlMs = (options.ttlSeconds || 900) * 1000;
  }

  isBlocked(ip) {
    if (this.allowlist.has(ip)) return false;
    const record = this.blocks.get(ip);
    if (!record) return false;
    if (Date.now() > record.expiresAt) {
      this.blocks.delete(ip);
      return false;
    }
    return record.reason;
  }

  blockIp(ip, reason) {
    this.blocks.set(ip, {
      ip,
      reason,
      blockedAt: Date.now(),
      expiresAt: Date.now() + this.defaultTtlMs
    });
  }

  unblockIp(ip) {
    return this.blocks.delete(ip);
  }

  middleware() {
    return (req, res, next) => {
      const clientIp = req.ip || req.connection.remoteAddress || '127.0.0.1';

      // 1. Check IP blocklist
      const blockReason = this.isBlocked(clientIp);
      if (blockReason && this.mode === 'block') {
        res.setHeader('X-Sentinel-Guard', 'blocked');
        return res.status(403).json({
          error: 'Forbidden',
          sentinel_shield: 'Access temporarily restricted by Sentinel Guard',
          reason: blockReason
        });
      }

      // 2. Inspect request
      const combined = `${req.method} ${req.url} ${JSON.stringify(req.query || {})} ${JSON.stringify(req.body || {})} ${req.headers['user-agent'] || ''}`;
      let score = 0;
      const triggered = [];

      for (const rule of FAST_RULES) {
        if (rule.regex.test(combined)) {
          score += rule.weight;
          triggered.push(rule.name);
        }
      }

      if (score >= this.blockThreshold && !this.allowlist.has(clientIp)) {
        if (this.mode === 'block') {
          this.blockIp(clientIp, `Triggered high anomaly: ${triggered.join(', ')}`);
          res.setHeader('X-Sentinel-Guard', 'blocked');
          return res.status(403).json({
            error: 'Forbidden',
            sentinel_shield: 'Threat blocked by Sentinel Guard'
          });
        }
      }

      res.setHeader('X-Sentinel-Risk-Score', String(score));
      next();
    };
  }
}

module.exports = { SentinelExpressGuard };
