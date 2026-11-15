// Local accounts: sign up, log in, log out, and the session cookie.
//
// Identity is resolved once per API request (resolveIdentity) and read back
// synchronously by index.js's userId(). Until the first account is created the
// app keeps its single-user behaviour, so nothing that worked before changes;
// the first account takes over the single user's existing projects.

const COOKIE = 'adis_session';
const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 310000;
export const DEMO_USER_ID = 'local-demo-user';

const identities = new WeakMap();
const failures = new Map();

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers },
});
const now = () => new Date().toISOString();
const hex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64url = (value) => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const sha256 = async (text) => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
const initials = (name) => name.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0].toUpperCase()).join('') || 'U';
const publicUser = (row) => ({ name: row.name, email: row.email, initials: initials(row.name) });

async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
}

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return ['pbkdf2-sha256', PBKDF2_ITERATIONS, b64url(salt), b64url(await derive(password, salt, PBKDF2_ITERATIONS))].join('$');
}

export async function verifyPassword(password, stored) {
  const [scheme, iterations, salt, expected] = String(stored || '').split('$');
  if (scheme !== 'pbkdf2-sha256' || !salt || !expected) return false;
  const actual = await derive(password, fromB64url(salt), Number(iterations));
  const wanted = fromB64url(expected);
  if (actual.length !== wanted.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i += 1) diff |= actual[i] ^ wanted[i];
  return diff === 0;
}

function cookieValue(req) {
  const header = req.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === COOKIE) return rest.join('=');
  }
  return '';
}

function sessionCookie(req, token, maxAge) {
  const secure = new URL(req.url).protocol === 'https:' ? '; Secure' : '';
  return COOKIE + '=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + maxAge + secure;
}

// Looks up the session cookie and whether any account exists. Called once per
// API request before any route runs.
export async function resolveIdentity(req, env) {
  let user = null;
  let accounts = false;
  try {
    accounts = Boolean(await env.DB.prepare('SELECT 1 AS found FROM users LIMIT 1').first());
    const token = cookieValue(req);
    if (accounts && token) {
      user = await env.DB.prepare('SELECT u.id,u.name,u.email FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?')
        .bind(await sha256(token), now()).first();
    }
  } catch (error) {
    // Before migration 0011 the tables do not exist: behave as before accounts.
    // Any other database error must not fall back to single-user access.
    if (!/no such table/i.test(String(error?.message))) throw error;
  }
  const identity = { user: user || null, accounts };
  identities.set(req, identity);
  return identity;
}

export const requestIdentity = (req) => identities.get(req) || null;

async function startSession(req, env, userId) {
  await env.DB.prepare('DELETE FROM user_sessions WHERE expires_at<=?').bind(now()).run();
  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const created = new Date();
  const expires = new Date(created.getTime() + SESSION_DAYS * 86400000);
  await env.DB.prepare('INSERT INTO user_sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)')
    .bind(await sha256(token), userId, created.toISOString(), expires.toISOString()).run();
  return sessionCookie(req, token, SESSION_DAYS * 86400);
}

// Used when no account matches, so a wrong email takes as long as a wrong password.
let dummyHash = null;
const dummy = async () => (dummyHash ||= await hashPassword('not-a-real-password'));

function throttled(email) {
  const entry = failures.get(email);
  return Boolean(entry && entry.count >= 5 && entry.until > Date.now());
}

function recordFailure(email) {
  const entry = failures.get(email);
  const count = entry && entry.until > Date.now() ? entry.count + 1 : 1;
  failures.set(email, { count, until: Date.now() + 60000 });
  if (failures.size > 5000) for (const [key, entry] of failures) if (entry.until <= Date.now()) failures.delete(key);
}

const cleanText = (value, max) => (typeof value === 'string' ? value.trim().slice(0, max) : '');

// Handles /api/auth/*. Returns null for any other path.
export async function authRoute(req, env, path, method) {
  if (!path.startsWith('/api/auth/')) return null;
  const identity = requestIdentity(req) || await resolveIdentity(req, env);
  const demo = String(env.LOCAL_DEMO_MODE || '').toLowerCase() === 'true';

  if (path === '/api/auth/me' && method === 'GET') {
    return json({ user: identity.user ? publicUser(identity.user) : null, accounts: identity.accounts, single_user: demo && !identity.accounts });
  }

  if (path === '/api/auth/signup' && method === 'POST') {
    const body = await req.json().catch(() => ({}));
    const name = cleanText(body.name, 80);
    const email = cleanText(body.email, 200).toLowerCase();
    const password = typeof body.password === 'string' ? body.password : '';
    if (!name) return json({ error: 'Enter your full name.' }, 400);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Enter a valid email address.' }, 400);
    if (password.length < 8) return json({ error: 'Use a password of at least 8 characters.' }, 400);
    if (password.length > 200) return json({ error: 'That password is too long.' }, 400);
    const existing = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
    if (existing) return json({ error: 'An account with that email already exists. Log in instead.' }, 409);
    const id = crypto.randomUUID();
    const first = !identity.accounts;
    try {
      await env.DB.prepare('INSERT INTO users(id,email,name,password_hash,created_at) VALUES(?,?,?,?,?)')
        .bind(id, email, name, await hashPassword(password), now()).run();
    } catch (error) {
      if (/UNIQUE constraint failed/i.test(String(error?.message))) return json({ error: 'An account with that email already exists. Log in instead.' }, 409);
      throw error;
    }
    // The first account takes over the projects created in single-user mode.
    if (first && demo) await env.DB.prepare('UPDATE projects SET user_id=? WHERE user_id=?').bind(id, DEMO_USER_ID).run();
    const cookie = await startSession(req, env, id);
    return json({ user: publicUser({ name, email }), claimed_projects: first && demo }, 201, { 'set-cookie': cookie });
  }

  if (path === '/api/auth/login' && method === 'POST') {
    const body = await req.json().catch(() => ({}));
    const email = cleanText(body.email, 200).toLowerCase();
    const password = typeof body.password === 'string' ? body.password : '';
    if (!email || !password) return json({ error: 'Enter your email and password.' }, 400);
    if (throttled(email)) return json({ error: 'Too many attempts. Wait a minute and try again.' }, 429);
    const user = await env.DB.prepare('SELECT id,name,email,password_hash FROM users WHERE email=?').bind(email).first();
    const valid = await verifyPassword(password, user ? user.password_hash : await dummy());
    if (!user || !valid) {
      recordFailure(email);
      return json({ error: 'That email and password do not match an account.' }, 401);
    }
    failures.delete(email);
    const cookie = await startSession(req, env, user.id);
    return json({ user: publicUser(user) }, 200, { 'set-cookie': cookie });
  }

  if (path === '/api/auth/logout' && method === 'POST') {
    const token = cookieValue(req);
    if (token) await env.DB.prepare('DELETE FROM user_sessions WHERE token_hash=?').bind(await sha256(token)).run();
    return json({ signed_out: true }, 200, { 'set-cookie': sessionCookie(req, '', 0) });
  }

  return json({ error: 'Not found.' }, 404);
}
