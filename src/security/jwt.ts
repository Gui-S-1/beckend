import { SignJWT, jwtVerify as joseVerify } from 'jose';

export type JwtPayload = {
  sub: string;
  tenant_id: string;
  username?: string;
  roles?: string[];
  email?: string;
  company_name?: string;
};

const secret = new TextEncoder().encode(process.env.JWT_SECRET || 'replace_me');

export async function jwtSign(payload: JwtPayload) {
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret);
}

export async function jwtVerify(token: string) {
  const { payload } = await joseVerify(token, secret);
  return payload as JwtPayload;
}
