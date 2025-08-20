import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';

export const helmetMw = helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "script-src": ["'self'"],
      "style-src": ["'self'", "'unsafe-inline'"]
    }
  },
  referrerPolicy: { policy: 'no-referrer' },
  crossOriginOpenerPolicy: { policy: 'same-origin' }
});

export const compressMw = compression();

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 20,                   // max 20 prób / IP
  standardHeaders: true,
  legacyHeaders: false,
  message: "Za dużo prób logowania. Spróbuj ponownie za chwilę."
});