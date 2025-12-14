import { RateLimiterMemory } from 'rate-limiter-flexible';
import type { Request, Response, NextFunction } from 'express';

const limiter = new RateLimiterMemory({ points: 100, duration: 60 });

export async function rateLimiterMiddleware(req: Request, res: Response, next: NextFunction) {
  try {
    const ip = req.ip || req.socket.remoteAddress || '0.0.0.0';
    await limiter.consume(ip);
    next();
  } catch {
    res.status(429).json({ error: 'too-many-requests' });
  }
}
