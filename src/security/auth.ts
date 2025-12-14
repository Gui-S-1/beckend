import { Request, Response, NextFunction } from 'express';
import { jwtVerify } from './jwt.js';

export interface AuthRequest extends Request {
  user?: {
    id: string;
    tenant_id: string;
    username: string;
    roles: string[];
  };
}

/**
 * Middleware de autenticação JWT
 * Valida token e anexa user na request
 */
export async function authMiddleware(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', message: 'Token não fornecido' });
  }

  const token = authHeader.substring(7);
  try {
    const payload = await jwtVerify(token);
    req.user = {
      id: payload.sub,
      tenant_id: payload.tenant_id,
      username: payload.username || '',
      roles: payload.roles || []
    };
    next();
  } catch (error) {
    return res.status(401).json({ error: 'unauthorized', message: 'Token inválido ou expirado' });
  }
}

/**
 * Middleware de autorização por role
 * Verifica se o usuário tem pelo menos um dos roles permitidos
 */
export function requireRoles(...allowedRoles: string[]) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    const hasRole = req.user.roles.some((role) => allowedRoles.includes(role));
    if (!hasRole) {
      return res.status(403).json({ 
        error: 'forbidden', 
        message: `Requer um dos roles: ${allowedRoles.join(', ')}` 
      });
    }

    next();
  };
}
