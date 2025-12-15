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

// ============= USUÁRIOS =============
// Listar todos os usuários do tenant
app.get('/users', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.name, u.active, u.created_at,
            ARRAY_AGG(r.code) AS roles
     FROM users u
     JOIN license_keys lk ON lk.id = u.key_id
     LEFT JOIN key_roles kr ON kr.key_id = lk.id
     LEFT JOIN roles r ON r.id = kr.role_id
     WHERE lk.tenant_id = $1
     GROUP BY u.id, u.username, u.name, u.active, u.created_at
     ORDER BY u.name`,
    [tenantId]
  );
  
  res.json({ ok: true, users: rows });
});

// ============= ORDENS DE SERVIÇO =============
// Listar OS com filtros baseados em role
app.get('/orders', authMiddleware, requireRoles('os', 'admin'), async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  const userId = req.user!.id;
  const userRoles = req.user!.roles || [];
  const { status } = req.query;
  
  let query = `
    SELECT o.id, o.title, o.description, o.sector, o.priority, o.status,
           o.started_at, o.finished_at, o.created_at, o.updated_at,
           u_req.name AS requested_by_name, u_req.id AS requested_by_id,
           COALESCE(
             json_agg(
               json_build_object('id', u_ass.id, 'name', u_ass.name)
             ) FILTER (WHERE u_ass.id IS NOT NULL), 
             '[]'
           ) AS assigned_to
    FROM orders o
    LEFT JOIN users u_req ON u_req.id = o.requested_by
    LEFT JOIN order_assignments oa ON oa.order_id = o.id
    LEFT JOIN users u_ass ON u_ass.id = oa.user_id
    WHERE o.tenant_id = $1
  `;
  
  const params: any[] = [tenantId];
  
  // Se não for admin, só vê suas próprias OS
  if (!userRoles.includes('admin')) {
    query += ` AND (o.requested_by = $2 OR oa.user_id = $2)`;
    params.push(userId);
  }
  
  // Filtro de status
  if (status && typeof status === 'string') {
    query += ` AND o.status = $${params.length + 1}`;
    params.push(status);
  }
  
  query += ` GROUP BY o.id, o.title, o.description, o.sector, o.priority, o.status,
                      o.started_at, o.finished_at, o.created_at, o.updated_at,
                      u_req.name, u_req.id
             ORDER BY o.created_at DESC`;
  
  const { rows } = await pool.query(query, params);
  res.json({ ok: true, orders: rows });
});

// Criar ordem de serviço
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
     RETURNING id, title, description, sector, priority, status, created_at`,
    [tenantId, title, description, sector, priority, userId]
  );

  await pool.query(
    `INSERT INTO audit_logs (tenant_id, user_id, action, table_name, record_id, meta)
     VALUES ($1, $2, 'create', 'orders', $3, $4)`,
    [tenantId, userId, rows[0].id, JSON.stringify({ title })]
  );

  res.json({ ok: true, order: rows[0] });
});

// Atualizar status e responsáveis de uma OS
app.patch('/orders/:id', authMiddleware, requireRoles('os', 'admin'), async (req: AuthRequest, res) => {
  const { id } = req.params;
  const schema = z.object({
    status: z.enum(['pending', 'in_progress', 'completed']).optional(),
    assigned_to: z.array(z.string().uuid()).optional() // Array de user IDs
  });
  
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: 'validation', details: parsed.error });
  }

  const { status, assigned_to } = parsed.data;
  const tenantId = req.user!.tenant_id;
  const userId = req.user!.id;
  
  // Verificar se a OS pertence ao tenant
  const { rows: orderCheck } = await pool.query(
    'SELECT id FROM orders WHERE id = $1 AND tenant_id = $2',
    [id, tenantId]
  );
  
  if (orderCheck.length === 0) {
    return res.status(404).json({ ok: false, error: 'Order not found' });
  }
  
  // Atualizar status
  if (status) {
    const now = new Date();
    let updateQuery = 'UPDATE orders SET status = $1, updated_at = $2';
    const updateParams: any[] = [status, now];
    
    // Se mudou para "in_progress", registra started_at
    if (status === 'in_progress') {
      updateQuery += ', started_at = COALESCE(started_at, $3)';
      updateParams.push(now);
    }
    
    // Se mudou para "completed", registra finished_at
    if (status === 'completed') {
      updateQuery += ', finished_at = $' + (updateParams.length + 1);
      updateParams.push(now);
    }
    
    updateQuery += ' WHERE id = $' + (updateParams.length + 1);
    updateParams.push(id);
    
    await pool.query(updateQuery, updateParams);
  }
  
  // Atualizar responsáveis
  if (assigned_to) {
    // Remover atribuições antigas
    await pool.query('DELETE FROM order_assignments WHERE order_id = $1', [id]);
    
    // Adicionar novas atribuições
    for (const assignedUserId of assigned_to) {
      await pool.query(
        'INSERT INTO order_assignments (order_id, user_id) VALUES ($1, $2)',
        [id, assignedUserId]
      );
    }
  }
  
  // Audit log
  await pool.query(
    `INSERT INTO audit_logs (tenant_id, user_id, action, table_name, record_id, meta)
     VALUES ($1, $2, 'update', 'orders', $3, $4)`,
    [tenantId, userId, id, JSON.stringify({ status, assigned_to })]
  );
  
  res.json({ ok: true });
});

// Deletar OS (apenas admin)
app.delete('/orders/:id', authMiddleware, requireRoles('admin'), async (req: AuthRequest, res) => {
  const { id } = req.params;
  const tenantId = req.user!.tenant_id;
  
  const { rowCount } = await pool.query(
    'DELETE FROM orders WHERE id = $1 AND tenant_id = $2',
    [id, tenantId]
  );
  
  if (rowCount === 0) {
    return res.status(404).json({ ok: false, error: 'Order not found' });
  }
  
  res.json({ ok: true });
});

// ============= INVENTÁRIO =============
app.get('/inventory', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  
  const { rows } = await pool.query(
    `SELECT id, sku, name, category, brand, quantity, unit, location, min_stock, specs, updated_at
     FROM inventory_items
     WHERE tenant_id = $1
     ORDER BY name`,
    [tenantId]
  );
  
  res.json({ ok: true, items: rows });
});

app.post('/inventory', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  const schema = z.object({
    sku: z.string(),
    name: z.string(),
    category: z.string(),
    brand: z.string().optional(),
    quantity: z.number(),
    unit: z.string(),
    min_stock: z.number().optional(),
    location: z.string().optional(),
    specs: z.string().optional()
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Dados inválidos' });

  const data = parsed.data;
  
  try {
    const { rows } = await pool.query(
      `INSERT INTO inventory_items (tenant_id, sku, name, category, brand, quantity, unit, min_stock, location, specs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id`,
      [tenantId, data.sku, data.name, data.category, data.brand || null, data.quantity, data.unit, data.min_stock || 0, data.location || null, data.specs || null]
    );

    await auditLogger(pool, tenantId, req.user!.id, 'inventory_create', { item_id: rows[0].id, sku: data.sku });
    res.json({ ok: true, item_id: rows[0].id });
  } catch (error: any) {
    console.error('Erro ao criar item:', error);
    res.status(500).json({ ok: false, error: 'Erro ao criar item' });
  }
});

app.put('/inventory/:id', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  const itemId = parseInt(req.params.id);
  const schema = z.object({ quantity: z.number() });
  
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Dados inválidos' });

  try {
    await pool.query(
      `UPDATE inventory_items SET quantity = $1, updated_at = NOW()
       WHERE id = $2 AND tenant_id = $3`,
      [parsed.data.quantity, itemId, tenantId]
    );

    await auditLogger(pool, tenantId, req.user!.id, 'inventory_update', { item_id: itemId, new_quantity: parsed.data.quantity });
    res.json({ ok: true });
  } catch (error: any) {
    console.error('Erro ao atualizar item:', error);
    res.status(500).json({ ok: false, error: 'Erro ao atualizar item' });
  }
});

app.delete('/inventory/:id', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  const itemId = parseInt(req.params.id);

  try {
    await pool.query(
      `DELETE FROM inventory_items WHERE id = $1 AND tenant_id = $2`,
      [itemId, tenantId]
    );

    await auditLogger(pool, tenantId, req.user!.id, 'inventory_delete', { item_id: itemId });
    res.json({ ok: true });
  } catch (error: any) {
    console.error('Erro ao excluir item:', error);
    res.status(500).json({ ok: false, error: 'Erro ao excluir item' });
  }
});

// Purchases (Compras)
app.get('/purchases', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  
  const { rows } = await pool.query(
    `SELECT p.*, u.username AS requested_by_name
     FROM purchases p
     LEFT JOIN users u ON u.id = p.requested_by
     WHERE p.tenant_id = $1
     ORDER BY p.created_at DESC`,
    [tenantId]
  );
  
  res.json({ ok: true, purchases: rows });
});

app.post('/purchases', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  const userId = req.user!.id;
  
  const schema = z.object({
    item_name: z.string(),
    quantity: z.number(),
    unit: z.string(),
    unit_price: z.number().optional(),
    total_cost: z.number().optional(),
    supplier: z.string().optional(),
    notes: z.string().optional()
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Dados inválidos' });

  const data = parsed.data;
  
  try {
    const { rows } = await pool.query(
      `INSERT INTO purchases (tenant_id, item_name, quantity, unit, unit_price, total_cost, supplier, notes, requested_by, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'analise')
       RETURNING id`,
      [tenantId, data.item_name, data.quantity, data.unit, data.unit_price || 0, data.total_cost || 0, data.supplier || null, data.notes || null, userId]
    );

    await auditLogger(pool, tenantId, userId, 'purchase_create', { purchase_id: rows[0].id });
    res.json({ ok: true, purchase_id: rows[0].id });
  } catch (error: any) {
    console.error('Erro ao criar requisição:', error);
    res.status(500).json({ ok: false, error: 'Erro ao criar requisição' });
  }
});

app.patch('/purchases/:id', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  const purchaseId = parseInt(req.params.id);
  const schema = z.object({ status: z.string() });
  
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Dados inválidos' });

  try {
    await pool.query(
      `UPDATE purchases SET status = $1 WHERE id = $2 AND tenant_id = $3`,
      [parsed.data.status, purchaseId, tenantId]
    );

    await auditLogger(pool, tenantId, req.user!.id, 'purchase_update', { purchase_id: purchaseId, new_status: parsed.data.status });
    res.json({ ok: true });
  } catch (error: any) {
    console.error('Erro ao atualizar requisição:', error);
    res.status(500).json({ ok: false, error: 'Erro ao atualizar requisição' });
  }
});

app.delete('/purchases/:id', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  const purchaseId = parseInt(req.params.id);

  try {
    await pool.query(
      `DELETE FROM purchases WHERE id = $1 AND tenant_id = $2`,
      [purchaseId, tenantId]
    );

    await auditLogger(pool, tenantId, req.user!.id, 'purchase_delete', { purchase_id: purchaseId });
    res.json({ ok: true });
  } catch (error: any) {
    console.error('Erro ao excluir requisição:', error);
    res.status(500).json({ ok: false, error: 'Erro ao excluir requisição' });
  }
});

// Preventives (Manutenções Preventivas)
app.get('/preventives', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  
  const { rows } = await pool.query(
    `SELECT * FROM preventives WHERE tenant_id = $1 ORDER BY next_date`,
    [tenantId]
  );
  
  res.json({ ok: true, preventives: rows });
});

app.post('/preventives', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  
  const schema = z.object({
    equipment_name: z.string(),
    maintenance_type: z.string(),
    frequency: z.string(),
    next_date: z.string(),
    responsible: z.string().optional(),
    checklist: z.string().optional()
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Dados inválidos' });

  const data = parsed.data;
  
  try {
    const { rows } = await pool.query(
      `INSERT INTO preventives (tenant_id, equipment_name, maintenance_type, frequency, next_date, responsible, checklist)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id`,
      [tenantId, data.equipment_name, data.maintenance_type, data.frequency, data.next_date, data.responsible || null, data.checklist || null]
    );

    await auditLogger(pool, tenantId, req.user!.id, 'preventive_create', { preventive_id: rows[0].id });
    res.json({ ok: true, preventive_id: rows[0].id });
  } catch (error: any) {
    console.error('Erro ao criar preventiva:', error);
    res.status(500).json({ ok: false, error: 'Erro ao criar preventiva' });
  }
});

app.post('/preventives/:id/complete', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  const preventiveId = parseInt(req.params.id);

  try {
    // Buscar preventiva atual
    const { rows } = await pool.query(
      `SELECT frequency, next_date FROM preventives WHERE id = $1 AND tenant_id = $2`,
      [preventiveId, tenantId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ ok: false, error: 'Preventiva não encontrada' });
    }

    const prev = rows[0];
    const currentNext = new Date(prev.next_date);
    let newNextDate = new Date(currentNext);

    // Calcular próxima data baseado na frequência
    switch (prev.frequency) {
      case 'semanal':
        newNextDate.setDate(newNextDate.getDate() + 7);
        break;
      case 'quinzenal':
        newNextDate.setDate(newNextDate.getDate() + 14);
        break;
      case 'mensal':
        newNextDate.setMonth(newNextDate.getMonth() + 1);
        break;
      case 'bimestral':
        newNextDate.setMonth(newNextDate.getMonth() + 2);
        break;
      case 'trimestral':
        newNextDate.setMonth(newNextDate.getMonth() + 3);
        break;
      case 'semestral':
        newNextDate.setMonth(newNextDate.getMonth() + 6);
        break;
      case 'anual':
        newNextDate.setFullYear(newNextDate.getFullYear() + 1);
        break;
    }

    // Atualizar preventiva
    await pool.query(
      `UPDATE preventives 
       SET last_date = CURRENT_DATE, next_date = $1, updated_at = NOW()
       WHERE id = $2 AND tenant_id = $3`,
      [newNextDate.toISOString().split('T')[0], preventiveId, tenantId]
    );

    await auditLogger(pool, tenantId, req.user!.id, 'preventive_complete', { preventive_id: preventiveId, next_date: newNextDate });
    res.json({ ok: true, next_date: newNextDate });
  } catch (error: any) {
    console.error('Erro ao concluir preventiva:', error);
    res.status(500).json({ ok: false, error: 'Erro ao concluir preventiva' });
  }
});

app.delete('/preventives/:id', authMiddleware, async (req: AuthRequest, res) => {
  const tenantId = req.user!.tenant_id;
  const preventiveId = parseInt(req.params.id);

  try {
    await pool.query(
      `DELETE FROM preventives WHERE id = $1 AND tenant_id = $2`,
      [preventiveId, tenantId]
    );

    await auditLogger(pool, tenantId, req.user!.id, 'preventive_delete', { preventive_id: preventiveId });
    res.json({ ok: true });
  } catch (error: any) {
    console.error('Erro ao excluir preventiva:', error);
    res.status(500).json({ ok: false, error: 'Erro ao excluir preventiva' });
  }
});

const PORT = process.env.PORT || 8080;
httpServer.listen(PORT, () => {
  console.log(`🚀 Backend listening on http://localhost:${PORT}`);
});
