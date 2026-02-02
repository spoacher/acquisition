import aj from '#config/arcjet.js';
import logger from '#config/logger.js';
import { slidingWindow } from '@arcjet/node';

const securityMiddleware = async (req, res, next) => {
  try {
    const role = req.user?.role || 'guest';
    let limit;
    let message;

    switch (role) {
      case 'admin':
        limit = 20;
        message = 'Admin rate limit exceeded (20 requests per minutes). Slow down!';
        break;
      case 'user':
        limit = 10;
        message = 'User rate limit exceeded (10 requests per minutes). Slow down!';
        break;
      default:
        limit = 5;
        message = 'Guest rate limit exceeded (5 requests per minutes). Slow down!';
        break;
    }

    const client = aj.withRule(slidingWindow({
      mode: 'LIVE',
      interval: '1m',
      max: limit,
      name: `${role}-rate-limit`
    }));

    const  decision = await client.protect(req);

    if(decision.isDenied() && decision.reason.isBot()){
      logger.warn('Bot request blocked', {ip: req.ip, path: req.path, userAgent: req.headers['user-agent']});
      return res.status(403).json({ error: 'Forbidden', message:'Bot traffic is not allowed' });
    }
    if(decision.isDenied() && decision.reason.isShield()){
      logger.warn('Shield request blocked', {ip: req.ip, path: req.path, method: req.method, userAgent: req.headers['user-agent']});
      return res.status(403).json({ error: 'Forbidden', message:'Shield traffic is not allowed' });
    }
    if(decision.isDenied() && decision.reason.isRateLimit()){
      logger.warn('Rate limit exceeded', {ip: req.ip, path: req.path, method: req.method, userAgent: req.headers['user-agent']});
      return res.status(429).json({ error: 'Too Many Requests', message });
    }
    next();
  } catch (err) {
    logger.error('Arcjet inspection error:', err);
    return res.status(500).json({ error: 'Internal server error', message:'Something went wrong in security middleware' });
  }
};

export default securityMiddleware;