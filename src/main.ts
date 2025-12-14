import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import { z } from 'zod';
import { Pool } from 'pg';
import bcrypt from 'bcrypt';
import { jwtSign, jwtVerify, type JwtPayload } from './security/jwt.js';
import { rateLimiterMiddleware } from './security/rateLimit.js';
import { auditLogger } from './security/audit.js';
import { whatsappAdapter } from './integrations/whatsapp.js';
import { authMiddleware, requireRoles, type AuthRequest } from './security/auth.js';

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet());
app.use(rateLimiterMiddleware);

const httpServer = createServer(app);
const wss = new WebSocketServer({ server: httpServer });

const useSsl = (process.env.DATABASE_URL || '').includes('sslmode=require');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://icarus:icarus_pass@localhost:5432/icarus',
  ssl: false  // Desabilitar SSL completamente para localhost
});

app.get('/health', (_, res) => res.json({ ok: true }));

// Key validation (licença)
app.post('/auth/validate-key', async (req, res) => {
  console.log('[validate-key] incoming', { ip: req.ip, body: req.body });
  const schema = z.object({ key: z.string().min(10) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid' });

  const { key } = parsed.data;
  const { rows } = await pool.query(
    `SELECT lk.id AS key_id, lk.key_code, lk.is_lifetime, lk.expires_at, lk.revoked,
            t.id AS tenant_id, t.name AS tenant_name,
            ARRAY_AGG(r.code) AS roles
     FROM license_keys lk
     JOIN tenants t ON t.id = lk.tenant_id
     LEFT JOIN key_roles kr ON kr.key_id = lk.id
     LEFT JOIN roles r ON r.id = kr.role_id
     WHERE lk.key_hash = crypt($1, lk.key_hash)
     GROUP BY lk.id, lk.key_code, lk.is_lifetime, lk.expires_at, lk.revoked, t.id, t.name`,
    [key]
  );
  if (rows.length === 0) return res.status(401).json({ ok: false, error: 'invalid-key' });

  const license = rows[0];
  if (license.revoked) return res.status(401).json({ ok: false, error: 'key-revoked' });
  
  if (!license.is_lifetime && license.expires_at) {
    const now = new Date();
    const expires = new Date(license.expires_at);
    if (now > expires) return res.status(401).json({ ok: false, error: 'key-expired' });
  }

  const response = { 
    ok: true, 
    key_id: license.key_id,
    tenant: license.tenant_name,
    roles: license.roles || [],
    is_lifetime: license.is_lifetime,
    expires_at: license.expires_at
  };
  console.log('[validate-key] success', response);
  res.json(response);
});

// Login (usuário dentro da key)
app.post('/auth/login', async (req, res) => {
  const schema = z.object({ 
    key_id: z.string().uuid(),
    username: z.string().min(2).max(50), 
    password: z.string().min(1).max(100) 
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'invalid' });
  
  const { key_id, username, password } = parsed.data;

  // SQL injection protegido por parametrized query ($1, $2)
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.password_hash, u.name, u.active, u.key_id,
            lk.tenant_id, t.name AS tenant_name,
            ARRAY_AGG(r.code) AS roles
     FROM users u
     JOIN license_keys lk ON lk.id = u.key_id
     JOIN tenants t ON t.id = lk.tenant_id
     LEFT JOIN key_roles kr ON kr.key_id = lk.id
     LEFT JOIN roles r ON r.id = kr.role_id
     WHERE u.key_id = $1 AND LOWER(u.username) = LOWER($2) AND u.active = true
     GROUP BY u.id, u.username, u.password_hash, u.name, u.active, u.key_id, lk.tenant_id, t.name`,
    [key_id, username]
  );
  if (!rows.length) return res.status(401).json({ ok: false, error: 'invalid-credentials' });
  
  const user = rows[0];
  
  // Validação de senha usando crypt (proteção contra timing attacks)
  const { rows: pwRows } = await pool.query(
    `SELECT (u.password_hash = crypt($1, u.password_hash)) AS valid
     FROM users u WHERE u.id = $2`,
    [password, user.id]
  );
  
  if (!pwRows[0]?.valid) {
    // Audit log de tentativa falha
    await pool.query(
      `INSERT INTO audit_logs (tenant_id, user_id, action, meta)
       VALUES ($1, NULL, 'login_failed', $2)`,
      [user.tenant_id, JSON.stringify({ username, ip: req.ip })]
    );
    return res.status(401).json({ ok: false, error: 'invalid-credentials' });
  }

  // Audit log de login bem-sucedido
  await pool.query(
    `INSERT INTO audit_logs (tenant_id, user_id, action, meta)
     VALUES ($1, $2, 'login_success', $3)`,
    [user.tenant_id, user.id, JSON.stringify({ ip: req.ip })]
  );

  const payload: JwtPayload = { 
    sub: user.id, 
    tenant_id: user.tenant_id, 
    username: user.username,
    roles: user.roles || []
  };
  const token = await jwtSign(payload);
  
  res.json({ 
    ok: true,
    token, 
    user: { 
      id: user.id, 
      name: user.name, 
      username: user.username,
      tenant: user.tenant_name,
      roles: user.roles || []
    } 
  });
});

// =============================================
// ROTAS PROTEGIDAS (requerem autenticação)
// =============================================

// Exemplo: Listar ordens de serviço (requer role 'os')
app.get('/orders', authMiddleware, requireRoles('os', 'admin'), async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  
  // SQL injection protegido por parametrized query
  const { rows } = await pool.query(
    `SELECT o.id, o.title, o.description, o.sector, o.priority, o.status,
            o.started_at, o.finished_at, o.created_at,
            u1.name AS requested_by_name,
            u2.name AS assigned_to_name
     FROM orders o
     LEFT JOIN users u1 ON u1.id = o.requested_by
     LEFT JOIN users u2 ON u2.id = o.assigned_to
     WHERE o.tenant_id = $1
     ORDER BY o.created_at DESC
     LIMIT 100`,
    [tenantId]
  );
  
  res.json({ ok: true, orders: rows });
});

// Criar ordem de serviço (requer role 'os')
app.post('/orders', authMiddleware, requireRoles('os', 'admin'), async (req: AuthRequest, res) => {
  const schema = z.object({
    title: z.string().min(3).max(200),
    description: z.string().optional(),
    sector: z.string().optional(),
    priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium')
  });
  
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: 'validation', details: parsed.error });
  }

  const { title, description, sector, priority } = parsed.data;
  const tenantId = req.user!.tenant_id;
  const userId = req.user!.id;

  const { rows } = await pool.query(
    `INSERT INTO orders (tenant_id, title, description, sector, priority, requested_by, status)
     VALUES ($1, $2, $3, $4, $5, $6, 'pending')
     RETURNING id, title, status, created_at`,
    [tenantId, title, description, sector, priority, userId]
  );

  // Audit log
  await pool.query(
    `INSERT INTO audit_logs (tenant_id, user_id, action, table_name, record_id, meta)
     VALUES ($1, $2, 'create', 'orders', $3, $4)`,
    [tenantId, userId, rows[0].id, JSON.stringify({ title })]
  );

  res.json({ ok: true, order: rows[0] });
});

// Exemplo: Inventário (requer role 'almoxarifado')
app.get('/inventory', authMiddleware, requireRoles('almoxarifado', 'admin'), async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  
  const { rows } = await pool.query(
    `SELECT id, sku, name, quantity, unit, location, min_stock, updated_at
     FROM inventory_items
     WHERE tenant_id = $1
     ORDER BY name`,
    [tenantId]
  );
  
  res.json({ ok: true, items: rows });
});

wss.on('connection', (ws: import('ws').WebSocket) => {
  ws.send(JSON.stringify({ type: 'welcome', msg: 'Icarus WS connected' }));
});

const PORT = process.env.PORT || 8080;
httpServer.listen(PORT, () => {
  console.log(`🚀 Backend listening on http://localhost:${PORT}`);
});
