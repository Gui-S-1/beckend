import { Pool } from 'pg';

export async function auditLogger(
  pool: Pool,
  tenantId: string | undefined,
  userId: string | undefined,
  action: string,
  metadata?: Record<string, any>
) {
  try {
    await pool.query(
      `INSERT INTO audit_logs (tenant_id, user_id, action, meta) VALUES ($1, $2, $3, $4)`,
      [tenantId || null, userId || null, action, metadata || {}]
    );
  } catch (error) {
    console.error('Audit log failed:', error);
  }
}
