import { shadowFetch } from './shadowfetch';

/* Cloudflare Worker implementation of gcli2api with D1 + password protection. */

interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string;
  CODE_ASSIST_ENDPOINT?: string;
  ASSETS: Fetcher;
}

const DEFAULT_TOKEN_URI = 'https://oauth2.googleapis.com/token';
const DEFAULT_CLIENT_ID =
  '681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com';
const DEFAULT_CLIENT_SECRET = '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'; // fallback for Google CLI authorized_user.json
const ANT_DEFAULT_CLIENT_ID =
  '1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com';
const ANT_DEFAULT_CLIENT_SECRET = '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';
const ANT_DEFAULT_SYSTEM_PROMPT =
  '你是聊天机器人，专门为用户提供聊天和情绪价值，协助进行小说创作或者角色扮演，也可以提供数学或者代码上的建议';
const ANT_DEFAULT_ENDPOINT = 'https://daily-cloudcode-pa.sandbox.googleapis.com';
const DEFAULT_SAMPLE_PASSWORD = 'PLEASE_CHANGE_ME';
const MIN_PASSWORD_LENGTH = 12;
const SESSION_COOKIE_NAME = 'session_token';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_ACCOUNT_RETRIES = 5;
const WEAK_PASSWORDS = new Set(
  ['password', 'changeme', 'admin', '123456', '123456789', 'qwerty', 'gcli2api', 'default', 'secret', 'demo'].map(
    (v) => v.toLowerCase(),
  ),
);

const HTTP_STATUS_TO_RPC: Record<number, string> = {
  400: 'INVALID_ARGUMENT',
  401: 'UNAUTHENTICATED',
  403: 'PERMISSION_DENIED',
  404: 'NOT_FOUND',
  409: 'ABORTED',
  412: 'FAILED_PRECONDITION',
  429: 'RESOURCE_EXHAUSTED',
  499: 'CANCELLED',
  500: 'INTERNAL',
  501: 'UNIMPLEMENTED',
  503: 'UNAVAILABLE',
  504: 'DEADLINE_EXCEEDED',
};

function isGoogleUrl(url: string): boolean {
  const hostname = new URL(url).hostname.toLowerCase();
  return hostname.includes('google');
}

async function fetchWithPrivacy(url: string, init: RequestInit): Promise<Response> {
  if (isGoogleUrl(url)) {
    return shadowFetch(url, init);
  }
  return fetch(url, init);
}

class RequestError extends Error {
  status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

let schemaReady: Promise<void> | null = null;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return handleOptions();
    }

    const passwordCheck = validateSecret(env.ADMIN_PASSWORD);
    if (!passwordCheck.ok) {
      return googleErrorResponse(500, passwordCheck.reason ?? 'Weak password configured');
    }

    if (url.pathname === '/login') {
      if (request.method === 'GET') {
        return serveAsset(request, env, '/login.html');
      }
      return new Response(null, { status: 405 });
    }

    if (url.pathname === '/api/login') {
      if (request.method === 'POST') {
        return handleLogin(request, env);
      }
      return new Response(null, { status: 405 });
    }

    if (url.pathname === '/logout') {
      return logoutResponse();
    }

    if (!(await isAuthorized(request, env.ADMIN_PASSWORD))) {
      if (
        request.method === 'GET' &&
        url.pathname !== '/login' &&
        !url.pathname.startsWith('/api/') &&
        !url.pathname.startsWith('/logout')
      ) {
        return redirectToLogin(url);
      }
      return unauthorizedResponse();
    }

    if (url.pathname === '/healthz') {
      return jsonResponse({ ok: true });
    }

    try {
      await ensureSchema(env);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to initialize schema';
      const status = error instanceof RequestError ? error.status : 500;
      return googleErrorResponse(status, message);
    }

    if (url.pathname.startsWith('/api/ant/accounts')) {
      return handleAntAccountApi(request, env);
    }

    if (url.pathname.startsWith('/ant/')) {
      return handleAntApi(request, env);
    }

    if (url.pathname === '/' || url.pathname === '/admin' || url.pathname.startsWith('/assets')) {
      return serveAsset(request, env);
    }

    if (url.pathname.startsWith('/api/accounts')) {
      return handleAccountApi(request, env);
    }

    if (
      url.pathname.startsWith('/raw/models/') ||
      url.pathname.startsWith('/v1beta/models/') ||
      url.pathname.startsWith('/v1/models/')
    ) {
      return handleGeminiProxy(request, env);
    }

    return googleErrorResponse(404, 'Not found');
  },
};

function handleOptions(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      ...corsHeaders(),
      'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, x-goog-api-key',
    },
  });
}

function validateSecret(secret: string | undefined): { ok: boolean; reason?: string } {
  const value = secret?.trim() ?? '';
  if (!value) return { ok: false, reason: 'ADMIN_PASSWORD is missing' };
  if (value === DEFAULT_SAMPLE_PASSWORD) {
    return { ok: false, reason: 'ADMIN_PASSWORD must be changed from the sample value' };
  }
  if (value.length < MIN_PASSWORD_LENGTH) {
    return { ok: false, reason: 'ADMIN_PASSWORD is too short (min 12 chars)' };
  }
  if (WEAK_PASSWORDS.has(value.toLowerCase())) {
    return { ok: false, reason: 'ADMIN_PASSWORD is too weak' };
  }
  return { ok: true };
}

function extractPassword(request: Request): string | null {
  const auth = request.headers.get('authorization');
  if (auth?.startsWith('Bearer ')) {
    return auth.slice('Bearer '.length).trim() || null;
  }
  const apiKey = request.headers.get('x-goog-api-key') ?? request.headers.get('x-api-key');
  if (apiKey) return apiKey.trim();
  const url = new URL(request.url);
  const keyParam = url.searchParams.get('key');
  if (keyParam) return keyParam.trim();
  return null;
}

async function isAuthorized(request: Request, secret: string): Promise<boolean> {
  const provided = extractPassword(request);
  if (provided && timingSafeEqual(provided, secret.trim())) {
    return true;
  }
  const session = getCookie(request.headers, SESSION_COOKIE_NAME);
  if (session) {
    return verifySessionToken(session, secret.trim());
  }
  return false;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function unauthorizedResponse(): Response {
  return googleErrorResponse(401, 'Unauthenticated', {
    extraHeaders: { 'WWW-Authenticate': 'Bearer realm="restricted", charset="UTF-8"' },
  });
}

function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
  };
}

function jsonResponse(body: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      ...corsHeaders(),
      ...(extraHeaders ?? {}),
    },
  });
}

function googleErrorResponse(
  status: number,
  message: string,
  options?: { statusText?: string; extraHeaders?: Record<string, string> },
): Response {
  const payload = {
    error: {
      code: status,
      message,
      status: HTTP_STATUS_TO_RPC[status] ?? (status >= 500 ? 'INTERNAL' : 'UNKNOWN'),
    },
  };
  return jsonResponse(payload, status, options?.extraHeaders);
}

async function serveAsset(request: Request, env: Env, overridePath?: string): Promise<Response> {
  const targetRequest =
    overridePath && overridePath !== request.url
      ? new Request(new URL(overridePath, request.url), request)
      : request;
  const assetResponse = await env.ASSETS.fetch(targetRequest);
  const headers = new Headers(assetResponse.headers);
  const isRoot =
    targetRequest.url.endsWith('/') ||
    targetRequest.url.endsWith('/index.html') ||
    targetRequest.url === request.url;
  headers.set('cache-control', isRoot ? 'no-store, max-age=0' : 'no-store');
  for (const [key, value] of Object.entries(corsHeaders())) {
    headers.set(key, value);
  }
  return new Response(assetResponse.body, { status: assetResponse.status, headers });
}

async function handleLogin(request: Request, env: Env): Promise<Response> {
  let body: any;
  try {
    body = await parseJson(request);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid JSON body';
    return googleErrorResponse(400, message);
  }
  const password = typeof body.password === 'string' ? body.password.trim() : '';
  if (!password) {
    return googleErrorResponse(400, 'password is required');
  }
  const expected = env.ADMIN_PASSWORD?.trim() ?? '';
  if (!timingSafeEqual(password, expected)) {
    return googleErrorResponse(401, 'Invalid password', {
      extraHeaders: { 'set-cookie': clearSessionCookie() },
    });
  }
  const token = await createSessionToken(expected, SESSION_TTL_MS);
  return jsonResponse({ ok: true }, 200, {
    'set-cookie': buildSessionCookie(token, SESSION_TTL_MS),
  });
}

function logoutResponse(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      ...corsHeaders(),
      'set-cookie': clearSessionCookie(),
      'cache-control': 'no-store',
    },
  });
}

function redirectToLogin(url: URL): Response {
  return new Response(null, {
    status: 302,
    headers: {
      location: new URL('/login', url).toString(),
      'cache-control': 'no-store',
      'set-cookie': clearSessionCookie(),
    },
  });
}

async function ensureSchema(env: Env): Promise<void> {
  if (!schemaReady) {
    schemaReady = (async () => {
      if (!env.DB || typeof env.DB.prepare !== 'function') {
        throw new RequestError('D1 binding "DB" is missing. Check wrangler.toml and bindings.', 500);
      }
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS accounts (
          id TEXT PRIMARY KEY,
          label TEXT NOT NULL UNIQUE,
          client_id TEXT NOT NULL,
          client_secret TEXT NOT NULL,
          refresh_token TEXT NOT NULL,
          token_uri TEXT NOT NULL DEFAULT '${DEFAULT_TOKEN_URI}',
          project_id TEXT NOT NULL,
          access_token TEXT,
          access_token_expires_at INTEGER,
          is_enabled INTEGER NOT NULL DEFAULT 1,
          last_error TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
      `).run();
      await env.DB.prepare(
        'CREATE INDEX IF NOT EXISTS accounts_enabled_idx ON accounts (is_enabled);',
      ).run();
      await env.DB.prepare(
        'CREATE INDEX IF NOT EXISTS accounts_label_idx ON accounts (label);',
      ).run();
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS ant_accounts (
          id TEXT PRIMARY KEY,
          label TEXT NOT NULL UNIQUE,
          user_id TEXT,
          user_email TEXT,
          access_token TEXT,
          refresh_token TEXT NOT NULL,
          expires_in INTEGER,
          access_token_expires_at INTEGER,
          is_enabled INTEGER NOT NULL DEFAULT 1,
          last_error TEXT,
          raw_json TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
      `).run();
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS ant_accounts_enabled_idx ON ant_accounts (is_enabled);').run();
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS ant_accounts_label_idx ON ant_accounts (label);').run();
    })();
  }
  await schemaReady;
}

type AccountRow = {
  id: string;
  label: string;
  client_id: string;
  client_secret: string;
  refresh_token: string;
  token_uri: string | null;
  project_id: string;
  access_token: string | null;
  access_token_expires_at: number | null;
  is_enabled: number;
  last_error: string | null;
  created_at: number;
  updated_at: number;
};

type AccountRecord = AccountRow;

type PublicAccount = {
  id: string;
  label: string;
  projectId: string;
  isEnabled: boolean;
  updatedAt: number;
  createdAt: number;
  lastError?: string | null;
};

type AntAccountRow = {
  id: string;
  label: string;
  user_id: string | null;
  user_email: string | null;
  access_token: string | null;
  refresh_token: string;
  expires_in: number | null;
  access_token_expires_at: number | null;
  is_enabled: number;
  last_error: string | null;
  raw_json: string | null;
  created_at: number;
  updated_at: number;
};

type AntAccountRecord = AntAccountRow;

type PublicAntAccount = {
  id: string;
  label: string;
  userId?: string | null;
  userEmail?: string | null;
  isEnabled: boolean;
  updatedAt: number;
  createdAt: number;
  lastError?: string | null;
};

async function handleAccountApi(request: Request, env: Env): Promise<Response> {
  try {
    const url = new URL(request.url);
    const segments = url.pathname.split('/').filter(Boolean); // ['api','accounts',':id',...]
    if (request.method === 'GET' && segments.length === 2) {
      const accounts = await listAccounts(env);
      return jsonResponse({ accounts });
    }
    if (request.method === 'POST' && segments.length === 2) {
      try {
        const payload = await parseJson(request);
        return createAccountHandler(payload, env);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid JSON body';
        return googleErrorResponse(400, message);
      }
    }
    if (request.method === 'POST' && segments.length === 3 && segments[2] === 'bulk') {
      try {
        const payload = await parseJson(request);
        return bulkCreateAccounts(payload, env);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid JSON body';
        return googleErrorResponse(400, message);
      }
    }
    if (segments.length >= 3) {
      const accountId = segments[2];
      if (request.method === 'DELETE' && segments.length === 3) {
        await deleteAccount(env, accountId);
        return new Response(null, { status: 204, headers: corsHeaders() });
      }
      if (request.method === 'PATCH' && segments.length === 4) {
        if (segments[3] === 'project') {
          let body: any;
          try {
            body = await parseJson(request);
          } catch (error) {
            const message = error instanceof Error ? error.message : 'Invalid JSON body';
            return googleErrorResponse(400, message);
          }
          const projectId = typeof body.projectId === 'string' ? body.projectId.trim() : '';
          if (!projectId) return googleErrorResponse(400, 'projectId is required');
          await updateProject(env, accountId, projectId);
          return new Response(null, { status: 204, headers: corsHeaders() });
        }
        if (segments[3] === 'enabled') {
          let body: any;
          try {
            body = await parseJson(request);
          } catch (error) {
            const message = error instanceof Error ? error.message : 'Invalid JSON body';
            return googleErrorResponse(400, message);
          }
          if (typeof body.enabled !== 'boolean') {
            return googleErrorResponse(400, 'enabled must be boolean');
          }
          await setEnabled(env, accountId, body.enabled);
          return new Response(null, { status: 204, headers: corsHeaders() });
        }
      }
      if (segments.length === 5 && segments[3] === 'credentials') {
        if (segments[4] === 'import' && request.method === 'POST') {
          let body: any;
          try {
            body = await parseJson(request);
          } catch (error) {
            const message = error instanceof Error ? error.message : 'Invalid JSON body';
            return googleErrorResponse(400, message);
          }
          try {
            await importCredentials(env, accountId, body);
            return new Response(null, { status: 204, headers: corsHeaders() });
          } catch (error) {
            if (error instanceof RequestError) {
              return googleErrorResponse(error.status, error.message);
            }
            const message = error instanceof Error ? error.message : 'Import failed';
            return googleErrorResponse(400, message);
          }
        }
        if (segments[4] === 'export' && request.method === 'GET') {
          try {
            const payload = await exportCredentials(env, accountId);
            return jsonResponse(payload);
          } catch (error) {
            if (error instanceof RequestError) {
              return googleErrorResponse(error.status, error.message);
            }
            const message = error instanceof Error ? error.message : 'Export failed';
            return googleErrorResponse(500, message);
          }
        }
      }
    }
    return googleErrorResponse(404, 'API route not found');
  } catch (error) {
    if (error instanceof RequestError) {
      return googleErrorResponse(error.status, error.message);
    }
    const detail = error instanceof Error ? error.message : String(error);
    return googleErrorResponse(
      500,
      `Internal error (check D1 binding/config): ${detail}`,
    );
  }
}

async function parseJson<T = any>(request: Request): Promise<T> {
  const text = await request.text();
  if (!text) {
    return {} as T;
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error('Invalid JSON body');
  }
}

async function createAccountHandler(body: any, env: Env): Promise<Response> {
  const label = typeof body.label === 'string' ? body.label.trim() : '';
  const projectId = typeof body.projectId === 'string' ? body.projectId.trim() : '';
  const authorized = body.authorizedUser;

  let credentials: {
    clientId: string;
    clientSecret: string;
    refreshToken: string;
    tokenUri?: string;
    projectId?: string;
  } | null = null;

  try {
    if (authorized) {
      credentials = parseAuthorizedUser(authorized);
    } else {
      const clientId = typeof body.clientId === 'string' ? body.clientId.trim() : '';
      const clientSecret = typeof body.clientSecret === 'string' ? body.clientSecret.trim() : '';
      const refreshToken = typeof body.refreshToken === 'string' ? body.refreshToken.trim() : '';
      const tokenUri =
        typeof body.tokenUri === 'string' && body.tokenUri.trim() ? body.tokenUri.trim() : undefined;
      if (!clientId || !clientSecret || !refreshToken) {
        return googleErrorResponse(400, 'clientId, clientSecret, and refreshToken are required');
      }
      credentials = { clientId, clientSecret, refreshToken, tokenUri };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid account payload';
    return googleErrorResponse(400, message);
  }

  if (!label) return googleErrorResponse(400, 'label is required');
  if (!credentials) return googleErrorResponse(400, 'Missing credentials');
  const effectiveProject = (projectId || credentials?.projectId || '').trim();
  if (!effectiveProject) return googleErrorResponse(400, 'projectId is required');

  try {
    const account = await saveAccount(env, label, credentials, effectiveProject);
    return jsonResponse({ account });
  } catch (error) {
    if (error instanceof RequestError) {
      return googleErrorResponse(error.status, error.message);
    }
    const message = error instanceof Error ? error.message : String(error);
    return googleErrorResponse(500, message);
  }
}

function parseAuthorizedUser(value: unknown): {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  projectId?: string;
  tokenUri?: string;
} {
  if (!value || typeof value !== 'object') {
    throw new Error('authorizedUser must be an object');
  }
  const record = value as Record<string, unknown>;
  const clientId =
    typeof record['client_id'] === 'string' && record['client_id'].trim()
      ? record['client_id'].trim()
      : typeof record['clientId'] === 'string' && (record['clientId'] as string).trim()
        ? (record['clientId'] as string).trim()
        : DEFAULT_CLIENT_ID;
  const clientSecret =
    typeof record['client_secret'] === 'string' && record['client_secret'].trim()
      ? record['client_secret'].trim()
      : typeof record['clientSecret'] === 'string' && (record['clientSecret'] as string).trim()
        ? (record['clientSecret'] as string).trim()
        : DEFAULT_CLIENT_SECRET;
  const refreshToken =
    typeof record['refresh_token'] === 'string' && record['refresh_token'].trim()
      ? record['refresh_token'].trim()
      : typeof record['refreshToken'] === 'string' && (record['refreshToken'] as string).trim()
        ? (record['refreshToken'] as string).trim()
        : '';
  const projectId =
    typeof record['project_id'] === 'string' && record['project_id'].trim()
      ? record['project_id'].trim()
      : typeof record['projectId'] === 'string' && (record['projectId'] as string).trim()
        ? (record['projectId'] as string).trim()
        : undefined;
  const tokenUri =
    typeof record['token_uri'] === 'string' && record['token_uri'].trim()
      ? record['token_uri'].trim()
      : typeof record['tokenUri'] === 'string' && (record['tokenUri'] as string).trim()
        ? (record['tokenUri'] as string).trim()
        : undefined;
  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error('authorizedUser is missing required fields');
  }
  return { clientId, clientSecret, refreshToken, projectId, tokenUri };
}

async function saveAccount(
  env: Env,
  label: string,
  credentials: { clientId: string; clientSecret: string; refreshToken: string; tokenUri?: string },
  projectId: string,
): Promise<PublicAccount> {
  const now = Date.now();
  const id = crypto.randomUUID();
  const tokenUri = credentials.tokenUri ?? DEFAULT_TOKEN_URI;
  try {
    await env.DB.prepare(
      `INSERT INTO accounts
        (id, label, client_id, client_secret, refresh_token, token_uri, project_id, is_enabled, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);`,
    )
      .bind(
        id,
        label,
        credentials.clientId,
        credentials.clientSecret,
        credentials.refreshToken,
        tokenUri,
        projectId,
        1,
        now,
        now,
      )
      .run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('UNIQUE') || message.includes('unique')) {
      throw new RequestError('label already exists', 400);
    }
    throw new RequestError('Failed to save account', 500);
  }

  return {
    id,
    label,
    projectId,
    isEnabled: true,
    createdAt: now,
    updatedAt: now,
  };
}

async function bulkCreateAccounts(body: any, env: Env): Promise<Response> {
  if (!body || typeof body !== 'object') {
    return googleErrorResponse(400, 'Body must be an object with creds');
  }
  const credsMap = body.creds;
  if (!credsMap || typeof credsMap !== 'object') {
    return googleErrorResponse(400, 'creds must be an object');
  }

  type BulkResult = {
    label: string;
    projectId?: string;
    status: 'created' | 'skipped' | 'failed';
    message?: string;
  };
  const results: BulkResult[] = [];
  let created = 0;
  let skipped = 0;
  let failed = 0;

  const labelCache: Record<string, { projectId: string; userEmail: string | null; fingerprint: string }> = {};
  const fingerprintCache = new Set<string>();

  for (const [key, entry] of Object.entries(credsMap as Record<string, any>)) {
    let labelUsed = sanitizeLabel(String(key));
    const content = (entry as any)?.content ?? entry;
    const userEmail =
      typeof (entry as any)?.status?.user_email === 'string'
        ? (entry as any).status.user_email.trim()
        : typeof (entry as any)?.user_email === 'string'
        ? (entry as any).user_email.trim()
        : null;
    const errorCodes = Array.isArray((entry as any)?.status?.error_codes)
      ? ((entry as any).status.error_codes as unknown[])
      : [];
    if (errorCodes.some((code) => code === 403 || code === '403')) {
      results.push({
        label: labelUsed,
        projectId: '',
        status: 'skipped',
        message: 'error_codes contains 403',
      });
      skipped += 1;
      continue;
    }
    try {
      const parsed = parseAuthorizedUser(content);
      const projectId =
        parsed.projectId?.trim() ||
        (typeof content?.project_id === 'string' ? content.project_id.trim() : '') ||
        (typeof content?.projectId === 'string' ? content.projectId.trim() : '') ||
        '';
      if (!projectId) {
        throw new RequestError('projectId is required', 400);
      }

      const explicitLabel = typeof (entry as any)?.label === 'string' ? (entry as any).label.trim() : '';
      const filenameLabel = stripExtension(String(key));
      labelUsed = sanitizeLabel(explicitLabel || projectId || filenameLabel || crypto.randomUUID().slice(0, 8));
      if (!labelUsed) {
        throw new RequestError('label is required', 400);
      }

      const fingerprint = buildFingerprint(parsed, projectId);
      if (fingerprintCache.has(fingerprint)) {
        results.push({
          label: labelUsed,
          projectId,
          status: 'skipped',
          message: 'duplicate credential fingerprint',
        });
        skipped += 1;
        continue;
      }

      if (await accountExistsByFingerprint(env, parsed, projectId)) {
        fingerprintCache.add(fingerprint);
        results.push({
          label: labelUsed,
          projectId,
          status: 'skipped',
          message: 'credential already exists',
        });
        skipped += 1;
        continue;
      }

      const existing = await getAccountByLabel(env, labelUsed);
      const existingFp = existing ? buildFingerprint(existingToCred(existing), existing.project_id ?? '') : null;
      const cached = labelCache[labelUsed];

      if ((existingFp && existingFp === fingerprint) || (cached && cached.fingerprint === fingerprint)) {
        results.push({
          label: labelUsed,
          projectId,
          status: 'skipped',
          message: 'duplicate credential with same label',
        });
        skipped += 1;
        continue;
      }

      let finalLabel = labelUsed;
      if (existing || (cached && cached.fingerprint !== fingerprint)) {
        finalLabel = `${labelUsed}-${randomSuffix()}`;
      }

      const account = await saveAccount(env, finalLabel, parsed, projectId);
      labelCache[finalLabel] = { projectId, userEmail, fingerprint };
      fingerprintCache.add(fingerprint);
      results.push({ label: account.label, projectId: account.projectId, status: 'created' });
      created += 1;
    } catch (error) {
      if (error instanceof RequestError && error.message === 'label already exists') {
        results.push({ label: labelUsed, status: 'skipped', message: 'label already exists' });
        skipped += 1;
      } else {
        const message = error instanceof Error ? error.message : 'unknown error';
        results.push({ label: labelUsed, status: 'failed', message });
        failed += 1;
      }
    }
  }

  return jsonResponse({
    total: Object.keys(credsMap).length,
    created,
    skipped,
    failed,
    results,
  });
}

async function listAccounts(env: Env): Promise<PublicAccount[]> {
  try {
    const result = await env.DB.prepare('SELECT * FROM accounts ORDER BY updated_at DESC').all<AccountRow>();
    const rows = result.results ?? [];
    return rows.map((row) => ({
      id: row.id,
      label: row.label,
      projectId: row.project_id,
      isEnabled: row.is_enabled === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      lastError: row.last_error,
    }));
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to list accounts';
    throw new RequestError(
      `Failed to list accounts (check D1 binding / wrangler version): ${message}`,
      500,
    );
  }
}

async function updateProject(env: Env, accountId: string, projectId: string): Promise<void> {
  const now = Date.now();
  const res = await env.DB.prepare(
    'UPDATE accounts SET project_id = ?1, updated_at = ?2 WHERE id = ?3;',
  )
    .bind(projectId, now, accountId)
    .run();
  if ((res as { success?: boolean }).success === false || d1Changes(res) === 0) {
    throw new RequestError('Account not found', 404);
  }
}

async function setEnabled(env: Env, accountId: string, enabled: boolean): Promise<void> {
  const now = Date.now();
  const res = await env.DB.prepare(
    'UPDATE accounts SET is_enabled = ?1, updated_at = ?2 WHERE id = ?3;',
  )
    .bind(enabled ? 1 : 0, now, accountId)
    .run();
  if ((res as { success?: boolean }).success === false || d1Changes(res) === 0) {
    throw new RequestError('Account not found', 404);
  }
}

async function deleteAccount(env: Env, accountId: string): Promise<void> {
  const res = await env.DB.prepare('DELETE FROM accounts WHERE id = ?1;').bind(accountId).run();
  if ((res as { success?: boolean }).success === false) {
    throw new RequestError('Failed to delete account', 500);
  }
  if (d1Changes(res) === 0) {
    throw new RequestError('Account not found', 404);
  }
}

async function importCredentials(env: Env, accountId: string, body: any): Promise<void> {
  const account = await getAccount(env, accountId);
  if (!account) throw new RequestError('Account not found', 404);
  const source = body?.authorizedUser ? body.authorizedUser : body;
  const parsed = parseAuthorizedUser(source);
  const project =
    typeof body?.projectId === 'string' && body.projectId.trim()
      ? body.projectId.trim()
      : typeof body?.project_id === 'string' && body.project_id.trim()
        ? body.project_id.trim()
        : parsed.projectId?.trim() || account.project_id;
  if (!project) {
    throw new RequestError('projectId is required', 400);
  }
  const now = Date.now();
  const res = await env.DB.prepare(
    `UPDATE accounts
     SET client_id = ?1,
         client_secret = ?2,
         refresh_token = ?3,
         token_uri = ?4,
         project_id = ?5,
         access_token = NULL,
         access_token_expires_at = NULL,
         last_error = NULL,
         updated_at = ?6
     WHERE id = ?7;`,
    )
    .bind(
      parsed.clientId,
      parsed.clientSecret,
      parsed.refreshToken,
      parsed.tokenUri ?? DEFAULT_TOKEN_URI,
      project,
      now,
      accountId,
    )
    .run();
  if ((res as { success?: boolean }).success === false || d1Changes(res) === 0) {
    throw new RequestError('Failed to update account', 500);
  }
}

async function exportCredentials(env: Env, accountId: string): Promise<Record<string, string>> {
  const account = await getAccount(env, accountId);
  if (!account) throw new RequestError('Account not found', 404);
  return {
    type: 'authorized_user',
    client_id: account.client_id,
    client_secret: account.client_secret,
    refresh_token: account.refresh_token,
    token_uri: account.token_uri || DEFAULT_TOKEN_URI,
    project_id: account.project_id,
  };
}

async function getAccount(env: Env, accountId: string): Promise<AccountRecord | null> {
  const res = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?1 LIMIT 1;')
    .bind(accountId)
    .all<AccountRow>();
  return res.results?.[0] ?? null;
}

async function handleGeminiProxy(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const route = parseModelRoute(url.pathname);
  if (!route) return googleErrorResponse(404, 'Invalid model route');

  let wantsStream =
    route.method === 'streamGenerateContent' ||
    url.searchParams.get('alt')?.toLowerCase() === 'sse';
  if (!wantsStream) {
    const streamQuery = url.searchParams.get('stream');
    if (
      typeof streamQuery === 'string' &&
      ['true', '1', 'yes', 'sse'].includes(streamQuery.toLowerCase())
    ) {
      wantsStream = true;
    }
  }

  let generatePayload: GenerateContentParameters | null = null;
  let countPayload: CountTokensParameters | null = null;
  let rawGenerateBody: any = null;

  try {
    if (route.method === 'generateContent' || route.method === 'streamGenerateContent') {
      rawGenerateBody = await parseJson(request);
      if (!wantsStream) {
        const streamFlag = rawGenerateBody?.stream;
        if (
          streamFlag === true ||
          streamFlag === 1 ||
          (typeof streamFlag === 'string' && ['true', '1', 'yes', 'sse'].includes(streamFlag.toLowerCase()))
        ) {
          wantsStream = true;
        }
      }
      generatePayload = normalizeGenerateContentRequest(rawGenerateBody, route.model);
    } else if (route.method === 'countTokens') {
      const body = await parseJson(request);
      countPayload = normalizeCountTokensRequest(body, route.model);
    }
  } catch (error) {
    if (error instanceof RequestError) {
      return googleErrorResponse(error.status, error.message);
    }
    const message = error instanceof Error ? error.message : 'Invalid JSON body';
    return googleErrorResponse(400, message);
  }

  let lastResponse: Response | null = null;
  const tried = new Set<string>();
  let attempts = 0;

  while (attempts < MAX_ACCOUNT_RETRIES) {
    attempts += 1;
    const account = await getRandomActiveAccount(env);
    if (!account) break;
    if (!tried.has(account.id)) {
      tried.add(account.id);
    }
    if (!account.project_id) {
      lastResponse = googleErrorResponse(400, 'Account is missing project_id');
      continue;
    }

    let token: string;
    try {
      token = await getValidAccessToken(env, account);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to refresh token';
      lastResponse = googleErrorResponse(500, message);
      continue;
    }

    try {
      if (route.method === 'countTokens') {
        const caRequest = toCountTokenRequest(countPayload as CountTokensParameters);
        const upstream = await callUpstream(env, 'countTokens', caRequest, token);
        if (!upstream.ok) {
          lastResponse = await forwardErrorResponse(upstream, env, account.id);
          continue;
        }
        await clearAccountError(env, account.id);
        const data = (await upstream.json()) as CaCountTokenResponse;
        return jsonResponse(fromCountTokenResponse(data));
      }

      if (route.method === 'generateContent' || route.method === 'streamGenerateContent') {
        const caRequest = toGenerateContentRequest(generatePayload as GenerateContentParameters, account.project_id);
        const upstreamMethod = wantsStream ? 'streamGenerateContent' : 'generateContent';

        if (wantsStream) {
          const upstream = await callUpstream(env, upstreamMethod, caRequest, token, true);
          if (!upstream.ok || !upstream.body) {
            lastResponse = await forwardErrorResponse(upstream, env, account.id);
            continue;
          }
          await clearAccountError(env, account.id);
          return await transformSseStream(upstream, fromGenerateContentResponse);
        }

        const upstream = await callUpstream(env, upstreamMethod, caRequest, token);
        if (!upstream.ok) {
          lastResponse = await forwardErrorResponse(upstream, env, account.id);
          continue;
        }
        await clearAccountError(env, account.id);
        const data = (await upstream.json()) as CaGenerateContentResponse;
        return jsonResponse(fromGenerateContentResponse(data));
      }
    } catch (error) {
      if (error instanceof RequestError) {
        return googleErrorResponse(error.status, error.message);
      }
      const message = error instanceof Error ? error.message : 'Internal error';
      lastResponse = googleErrorResponse(500, message);
      continue;
    }
  }

  if (lastResponse) return lastResponse;
  return googleErrorResponse(503, 'No active accounts available');
}

type ModelRoute = { model: string; method: 'generateContent' | 'streamGenerateContent' | 'countTokens' };

function parseModelRoute(pathname: string): ModelRoute | null {
  let segment: string | null = null;
  if (pathname.startsWith('/raw/models/')) {
    segment = pathname.slice('/raw/models/'.length);
  } else if (pathname.startsWith('/v1beta/models/')) {
    segment = pathname.slice('/v1beta/models/'.length);
  } else if (pathname.startsWith('/v1/models/')) {
    segment = pathname.slice('/v1/models/'.length);
  }
  if (!segment) return null;
  const parts = segment.split('/');
  const modelPart = parts[0] ?? '';
  if (!modelPart) return null;
  const [rawModel, maybeMethod] = modelPart.split(':');
  const method = (maybeMethod ?? 'generateContent') as ModelRoute['method'];
  return { model: stripModelPrefix(rawModel), method };
}

function stripModelPrefix(model: string): string {
  return model.startsWith('models/') ? model.slice('models/'.length) : model;
}

async function forwardErrorResponse(
  upstream: Response,
  env?: Env,
  accountId?: string,
): Promise<Response> {
  const text = await upstream.text();
  let parsed: any;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
  }
  const status = upstream.status || 500;
  const message =
    parsed?.error?.message ||
    (typeof parsed === 'string' && parsed) ||
    text ||
    `Upstream error ${status}`;
  if (env && accountId) {
    const now = Date.now();
    const reason = message.slice(0, 500);
    if (status === 403) {
      await env.DB.prepare(
        'UPDATE accounts SET is_enabled = 0, last_error = ?1, updated_at = ?2 WHERE id = ?3;',
      )
        .bind(reason, now, accountId)
        .run();
    } else {
      await env.DB.prepare('UPDATE accounts SET last_error = ?1, updated_at = ?2 WHERE id = ?3;')
        .bind(reason, now, accountId)
        .run();
    }
  }
  return googleErrorResponse(status, message);
}

async function getRandomActiveAccount(env: Env): Promise<AccountRecord | null> {
  try {
    const result = await env.DB.prepare(
      'SELECT * FROM accounts WHERE is_enabled = 1 ORDER BY random() LIMIT 1;',
    ).all<AccountRow>();
    const row = result.results?.[0];
    return row ?? null;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to select account';
    throw new RequestError(
      `Failed to select account (check D1 binding / wrangler version): ${message}`,
      500,
    );
  }
}

async function getValidAccessToken(env: Env, account: AccountRecord): Promise<string> {
  const now = Date.now();
  if (account.access_token && account.access_token_expires_at && account.access_token_expires_at - 60_000 > now) {
    return account.access_token;
  }
  const refreshed = await refreshAccessToken(env, account);
  return refreshed;
}

async function refreshAccessToken(env: Env, account: AccountRecord): Promise<string> {
  const params = new URLSearchParams();
  params.set('client_id', account.client_id);
  params.set('client_secret', account.client_secret);
  params.set('refresh_token', account.refresh_token);
  params.set('grant_type', 'refresh_token');
  const tokenUri = account.token_uri || DEFAULT_TOKEN_URI;
  const response = await fetchWithPrivacy(tokenUri, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: params,
  });
  if (!response.ok) {
    const text = await response.text();
    const message = `Failed to refresh token (${response.status}): ${text || 'unknown error'}`;
    const now = Date.now();
    if (response.status === 403) {
      await env.DB.prepare(
        'UPDATE accounts SET is_enabled = 0, last_error = ?1, updated_at = ?2 WHERE id = ?3;',
      )
        .bind(message.slice(0, 500), now, account.id)
        .run();
    } else {
      await env.DB.prepare('UPDATE accounts SET last_error = ?1, updated_at = ?2 WHERE id = ?3;')
        .bind(message.slice(0, 500), now, account.id)
        .run();
    }
    throw new Error(message);
  }
  const data = (await response.json()) as { access_token?: string; expires_in?: number };
  if (!data.access_token) {
    throw new Error('No access_token returned from Google');
  }
  const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 3600;
  const expiresAt = Date.now() + (expiresIn - 60) * 1000;
  await env.DB.prepare(
    'UPDATE accounts SET access_token = ?1, access_token_expires_at = ?2, updated_at = ?3 WHERE id = ?4;',
  )
    .bind(data.access_token, expiresAt, Date.now(), account.id)
    .run();
  account.access_token = data.access_token;
  account.access_token_expires_at = expiresAt;
  return data.access_token;
}

async function clearAccountError(env: Env, accountId: string): Promise<void> {
  await env.DB.prepare('UPDATE accounts SET last_error = NULL, updated_at = ?1 WHERE id = ?2;')
    .bind(Date.now(), accountId)
    .run();
}

type GenerateContentParameters = {
  model: string;
  contents: ContentListUnion;
  config?: GenerateContentConfig;
  generationConfig?: Partial<GenerateContentConfig>;
  [key: string]: unknown;
};

type CountTokensParameters = {
  model: string;
  contents: ContentListUnion;
  [key: string]: unknown;
};

type ContentListUnion = ContentUnion | ContentUnion[];
type ContentUnion = Content | PartUnion[] | PartUnion | string;
type Content = { role?: string; parts?: PartUnion[] | undefined };
type PartUnion = Part | string | (Part & { thought?: string });
type Part = { text?: string; [key: string]: unknown };

type GenerateContentConfig = Record<string, unknown>;

const DIRECT_CONFIG_FIELDS = [
  'systemInstruction',
  'cachedContent',
  'tools',
  'toolConfig',
  'labels',
  'safetySettings',
  'responseModalities',
  'mediaResolution',
  'speechConfig',
  'audioTimestamp',
  'automaticFunctionCalling',
  'thinkingConfig',
  'imageConfig',
] as const;

const GENERATION_CONFIG_FIELDS = [
  'temperature',
  'topP',
  'topK',
  'candidateCount',
  'maxOutputTokens',
  'stopSequences',
  'responseLogprobs',
  'logprobs',
  'presencePenalty',
  'frequencyPenalty',
  'seed',
  'responseMimeType',
  'responseSchema',
  'responseJsonSchema',
  'routingConfig',
  'modelSelectionConfig',
  'responseModalities',
  'mediaResolution',
  'speechConfig',
  'audioTimestamp',
  'automaticFunctionCalling',
  'thinkingConfig',
  'imageConfig',
] as const;

function normalizeGenerateContentRequest(body: any, pathModel: string): GenerateContentParameters {
  if (!body || typeof body !== 'object') {
    throw new RequestError('Request body must be a JSON object', 400);
  }
  const model = typeof body.model === 'string' && body.model.trim() ? stripModelPrefix(body.model.trim()) : pathModel;
  if (!model) throw new RequestError('model is required', 400);
  if (body.contents === undefined || body.contents === null) {
    throw new RequestError('contents is required', 400);
  }

  const config: GenerateContentConfig = body.config ? { ...body.config } : {};
  for (const key of DIRECT_CONFIG_FIELDS) {
    if (body[key] !== undefined) {
      config[key] = body[key];
    }
  }
  const generation = body.generationConfig;
  if (generation && typeof generation === 'object') {
    for (const key of GENERATION_CONFIG_FIELDS) {
      if ((generation as Record<string, unknown>)[key] !== undefined) {
        config[key] = (generation as Record<string, unknown>)[key];
      }
    }
  }
  const normalized: GenerateContentParameters = {
    model,
    contents: body.contents as ContentListUnion,
  };
  if (Object.keys(config).length > 0) {
    normalized.config = config;
  }
  return normalized;
}

function normalizeCountTokensRequest(body: any, pathModel: string): CountTokensParameters {
  if (!body || typeof body !== 'object') {
    throw new RequestError('Request body must be a JSON object', 400);
  }
  const model = typeof body.model === 'string' && body.model.trim() ? stripModelPrefix(body.model.trim()) : pathModel;
  if (!model) throw new RequestError('model is required', 400);

  if (body.generateContentRequest) {
    const nested = body.generateContentRequest;
    if (!nested.model) nested.model = model;
    const normalized = normalizeGenerateContentRequest(nested, model);
    return { model: normalized.model, contents: normalized.contents };
  }

  if (body.contents === undefined || body.contents === null) {
    throw new RequestError('contents is required', 400);
  }
  const normalized = normalizeGenerateContentRequest(body, model);
  return { model: normalized.model, contents: normalized.contents };
}

function toGenerateContentRequest(
  req: GenerateContentParameters,
  project: string,
): CAGenerateContentRequest {
  return {
    model: req.model,
    project,
    user_prompt_id: crypto.randomUUID(),
    request: toVertexGenerateContentRequest(req),
  };
}

function toVertexGenerateContentRequest(req: GenerateContentParameters): VertexGenerateContentRequest {
  const cachedContent = typeof req.config?.cachedContent === 'string' ? req.config.cachedContent : undefined;
  const labels =
    req.config?.labels && typeof req.config.labels === 'object' && !Array.isArray(req.config.labels)
      ? (Object.fromEntries(
          Object.entries(req.config.labels as Record<string, unknown>).filter(([, v]) => typeof v === 'string'),
        ) as Record<string, string>)
      : undefined;
  return {
    contents: toContents(req.contents),
    systemInstruction: maybeToContent(req.config?.systemInstruction),
    cachedContent,
    tools: req.config?.tools,
    toolConfig: req.config?.toolConfig,
    labels,
    safetySettings: req.config?.safetySettings,
    generationConfig: toVertexGenerationConfig(req.config),
  };
}

function toContents(contents: ContentListUnion): Content[] {
  if (Array.isArray(contents)) {
    return contents.map(toContent);
  }
  return [toContent(contents)];
}

function maybeToContent(content: unknown): Content | undefined {
  if (!content) return undefined;
  return toContent(content as ContentUnion);
}

function toContent(content: ContentUnion): Content {
  if (Array.isArray(content)) {
    return { role: 'user', parts: toParts(content) };
  }
  if (typeof content === 'string') {
    return { role: 'user', parts: [{ text: content }] };
  }
  if ('parts' in (content as Content)) {
    const c = content as Content;
    return {
      ...c,
      parts: c.parts ? toParts(c.parts as PartUnion[]) : [],
    };
  }
  return { role: 'user', parts: toParts([content as PartUnion]) };
}

function toParts(parts: PartUnion[]): Part[] {
  return parts.map(toPart);
}

function toPart(part: PartUnion): Part {
  if (typeof part === 'string') {
    return { text: part };
  }
  if ('thought' in (part as Record<string, unknown>) && (part as Record<string, unknown>).thought) {
    const thoughtText = `[Thought: ${(part as Record<string, unknown>).thought}]`;
    const copy: Record<string, unknown> = { ...(part as Record<string, unknown>) };
    delete copy.thought;
    const hasApiContent =
      'functionCall' in copy || 'functionResponse' in copy || 'inlineData' in copy || 'fileData' in copy;
    if (hasApiContent) return copy as Part;
    const existing = typeof copy.text === 'string' ? copy.text : '';
    return { ...copy, text: existing ? `${existing}\n${thoughtText}` : thoughtText };
  }
  return part as Part;
}

function toVertexGenerationConfig(config?: GenerateContentConfig): Record<string, unknown> | undefined {
  if (!config) return undefined;
  const clean: Record<string, unknown> = {};
  for (const key of GENERATION_CONFIG_FIELDS) {
    if ((config as Record<string, unknown>)[key] !== undefined) {
      clean[key] = (config as Record<string, unknown>)[key];
    }
  }
  return Object.keys(clean).length ? clean : undefined;
}

type CAGenerateContentRequest = {
  model: string;
  project?: string;
  user_prompt_id?: string;
  request: VertexGenerateContentRequest;
};

type VertexGenerateContentRequest = {
  contents: Content[];
  systemInstruction?: Content;
  cachedContent?: string;
  tools?: unknown;
  toolConfig?: unknown;
  labels?: Record<string, string>;
  safetySettings?: unknown;
  generationConfig?: Record<string, unknown>;
};

type CaGenerateContentResponse = {
  response: {
    candidates?: unknown[];
    automaticFunctionCallingHistory?: unknown[];
    promptFeedback?: unknown;
    usageMetadata?: unknown;
    modelVersion?: string;
  };
  traceId?: string;
};

type CaCountTokenRequest = { request: { model: string; contents: Content[] } };
type CaCountTokenResponse = { totalTokens: number };

function toCountTokenRequest(req: CountTokensParameters): CaCountTokenRequest {
  return {
    request: {
      model: `models/${req.model}`,
      contents: toContents(req.contents),
    },
  };
}

function fromGenerateContentResponse(res: CaGenerateContentResponse): Record<string, unknown> {
  const inner = res.response ?? {};
  return {
    candidates: inner.candidates ?? [],
    automaticFunctionCallingHistory: inner.automaticFunctionCallingHistory,
    promptFeedback: inner.promptFeedback,
    usageMetadata: inner.usageMetadata,
    modelVersion: inner.modelVersion,
    responseId: res.traceId,
  };
}

function fromCountTokenResponse(res: CaCountTokenResponse): Record<string, unknown> {
  return { totalTokens: res.totalTokens ?? 0 };
}

async function callUpstream(
  env: Env,
  method: string,
  payload: unknown,
  accessToken: string,
  stream = false,
): Promise<Response> {
  const base = env.CODE_ASSIST_ENDPOINT?.trim() || 'https://cloudcode-pa.googleapis.com';
  const url = `${base}/v1internal:${method}${stream ? '?alt=sse' : ''}`;
  return fetchWithPrivacy(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${accessToken}`,
      'user-agent': 'gcli2api-worker/1.0',
      'x-goog-api-client': 'gcli2api-worker/1.0',
    },
    body: JSON.stringify(payload),
  });
}

async function transformSseStream(
  upstream: Response,
  mapChunk: (input: CaGenerateContentResponse) => Record<string, unknown>,
): Promise<Response> {
  const body = upstream.body;
  if (!body) {
    return googleErrorResponse(500, 'Upstream stream missing body');
  }
  const { readable, writable } = new TransformStream();
  const reader = body.getReader();
  const writer = writable.getWriter();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let buffer = '';
  let dataBuffer: string[] = [];
  let sentDone = false;

  const writeData = async (payload: unknown) => {
    const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
    await writer.write(encoder.encode(`data: ${text}\n\n`));
  };

  (async () => {
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          buffer += decoder.decode();
        } else {
          buffer += decoder.decode(value, { stream: true });
        }
        let idx;
        while ((idx = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 1);
          const trimmed = line.replace(/\r$/, '');
          if (trimmed.startsWith('data:')) {
            dataBuffer.push(trimmed.slice(5).trim());
          } else if (trimmed === '') {
            if (!dataBuffer.length) continue;
            const chunk = dataBuffer.join('\n');
            dataBuffer = [];
            if (chunk === '[DONE]') {
              await writeData('[DONE]');
              sentDone = true;
              break;
            }
            try {
              const parsed = JSON.parse(chunk) as CaGenerateContentResponse;
              const mapped = mapChunk(parsed);
              await writeData(mapped);
            } catch {
              // skip malformed chunk
            }
          }
        }
        if (done || sentDone) {
          break;
        }
      }
    } catch {
      // swallow pump errors; client will see stream end
    } finally {
      if (!sentDone) {
        await writeData('[DONE]');
      }
      reader.releaseLock();
      await writer.close();
    }
  })();

  const headers = new Headers({
    'content-type': 'text/event-stream',
    'cache-control': 'no-store',
    ...corsHeaders(),
  });
  return new Response(readable, { status: 200, headers });
}

function getCookie(headers: Headers, name: string): string | null {
  const cookieHeader = headers.get('cookie');
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const [key, ...rest] = part.split('=');
    if (key && key.trim() === name) {
      return rest.join('=').trim() || null;
    }
  }
  return null;
}

function buildSessionCookie(token: string, ttlMs: number): string {
  const maxAge = Math.floor(ttlMs / 1000);
  return `${SESSION_COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

function clearSessionCookie(): string {
  return `${SESSION_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}

async function createSessionToken(secret: string, ttlMs: number): Promise<string> {
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + ttlMs;
  const payload = `${sessionId}.${expiresAt}`;
  const signature = await signToken(payload, secret);
  return `${payload}.${signature}`;
}

async function verifySessionToken(token: string, secret: string): Promise<boolean> {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [sessionId, expRaw, signature] = parts;
  if (!sessionId || !signature) return false;
  const expiresAt = Number(expRaw);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return false;
  const payload = `${sessionId}.${expiresAt}`;
  const expected = await signToken(payload, secret);
  return timingSafeEqual(signature, expected);
}

async function signToken(payload: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const raw = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return bufferToBase64Url(raw);
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function d1Changes(res: { meta?: { changes?: number }; changes?: number }): number {
  if (typeof res.meta?.changes === 'number') return res.meta.changes;
  if (typeof res.changes === 'number') return res.changes;
  return 0;
}

function stripExtension(name: string): string {
  const idx = name.lastIndexOf('.');
  return idx === -1 ? name : name.slice(0, idx);
}

function sanitizeLabel(label: string): string {
  return label.trim();
}

async function getAccountByLabel(env: Env, label: string): Promise<AccountRecord | null> {
  const res = await env.DB.prepare('SELECT * FROM accounts WHERE label = ?1 LIMIT 1;')
    .bind(label)
    .all<AccountRow>();
  return res.results?.[0] ?? null;
}

async function accountExistsByFingerprint(
  env: Env,
  cred: { clientId: string; clientSecret: string; refreshToken: string; tokenUri?: string },
  projectId: string,
): Promise<boolean> {
  const tokenUri = cred.tokenUri ?? DEFAULT_TOKEN_URI;
  const res = await env.DB.prepare(
    `SELECT 1 FROM accounts
     WHERE client_id = ?1
       AND client_secret = ?2
       AND refresh_token = ?3
       AND COALESCE(token_uri, ?) = ?
       AND project_id = ?
     LIMIT 1;`,
  )
    .bind(cred.clientId, cred.clientSecret, cred.refreshToken, DEFAULT_TOKEN_URI, tokenUri, projectId)
    .all();
  return Boolean(res.results && res.results.length);
}

function existingToCred(account: AccountRecord): {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  tokenUri?: string;
} {
  return {
    clientId: account.client_id,
    clientSecret: account.client_secret,
    refreshToken: account.refresh_token,
    tokenUri: account.token_uri ?? DEFAULT_TOKEN_URI,
  };
}

function buildFingerprint(
  cred: { clientId: string; clientSecret: string; refreshToken: string; tokenUri?: string },
  projectId: string,
): string {
  const tokenUri = cred.tokenUri ?? DEFAULT_TOKEN_URI;
  return [cred.clientId, cred.clientSecret, cred.refreshToken, tokenUri, projectId || ''].join('|');
}

function randomSuffix(): string {
  return crypto.randomUUID().slice(0, 5);
}

/* ========= Antigravity client support ========= */

async function handleAntAccountApi(request: Request, env: Env): Promise<Response> {
  try {
    const url = new URL(request.url);
    const segments = url.pathname.split('/').filter(Boolean); // ['api','ant','accounts',...]
    if (request.method === 'GET' && segments.length === 3) {
      const accounts = await listAntAccounts(env);
      return jsonResponse({ accounts });
    }
    if (request.method === 'POST' && segments.length === 4 && segments[3] === 'import') {
      let body: any;
      try {
        body = await parseJson(request);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid JSON body';
        return googleErrorResponse(400, message);
      }
      try {
        return await importAntAccounts(env, body);
      } catch (error) {
        if (error instanceof RequestError) {
          return googleErrorResponse(error.status, error.message);
        }
        const message = error instanceof Error ? error.message : 'Import failed';
        return googleErrorResponse(400, message);
      }
    }
    if (segments.length >= 4) {
      const accountId = segments[3];
      if (segments.length === 4 && request.method === 'DELETE') {
        await deleteAntAccount(env, accountId);
        return new Response(null, { status: 204, headers: corsHeaders() });
      }
      if (segments.length === 5 && segments[4] === 'enabled' && request.method === 'PATCH') {
        let body: any;
        try {
          body = await parseJson(request);
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Invalid JSON body';
          return googleErrorResponse(400, message);
        }
        if (typeof body.enabled !== 'boolean') {
          return googleErrorResponse(400, 'enabled must be boolean');
        }
        await setAntEnabled(env, accountId, body.enabled);
        return new Response(null, { status: 204, headers: corsHeaders() });
      }
      if (segments.length === 5 && segments[4] === 'export' && request.method === 'GET') {
        try {
          const payload = await exportAntAccount(env, accountId);
          return jsonResponse(payload);
        } catch (error) {
          if (error instanceof RequestError) {
            return googleErrorResponse(error.status, error.message);
          }
          const message = error instanceof Error ? error.message : 'Export failed';
          return googleErrorResponse(500, message);
        }
      }
    }
    return googleErrorResponse(404, 'API route not found');
  } catch (error) {
    if (error instanceof RequestError) {
      return googleErrorResponse(error.status, error.message);
    }
    const detail = error instanceof Error ? error.message : String(error);
    return googleErrorResponse(
      500,
      `Internal error (check D1 binding/config): ${detail}`,
    );
  }
}

async function handleAntApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === '/ant/v1/chat/completions' && request.method === 'POST') {
    return handleAntChatCompletion(request, env);
  }
  if (url.pathname === '/ant/v1/models' && request.method === 'GET') {
    return handleAntModels(env);
  }
  return googleErrorResponse(404, 'Not found');
}

async function listAntAccounts(env: Env): Promise<PublicAntAccount[]> {
  try {
    const result = await env.DB.prepare('SELECT * FROM ant_accounts ORDER BY updated_at DESC').all<AntAccountRow>();
    const rows = result.results ?? [];
    return rows.map((row) => ({
      id: row.id,
      label: row.label,
      userId: row.user_id,
      userEmail: row.user_email,
      isEnabled: row.is_enabled === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      lastError: row.last_error,
    }));
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to list ant accounts';
    throw new RequestError(
      `Failed to list ant accounts (check D1 binding / wrangler version): ${message}`,
      500,
    );
  }
}

async function importAntAccounts(env: Env, payload: any): Promise<Response> {
  const parsed = parseAntAccounts(payload);
  if (!parsed.length) {
    throw new RequestError('No valid Antigravity credentials found', 400);
  }
  const refreshCache = new Set<string>();
  const labelCache: Record<string, boolean> = {};
  const results: Array<{ label: string; status: string; message?: string }> = [];
  let created = 0;
  let skipped = 0;
  let failed = 0;

  for (const entry of parsed) {
    const refreshToken = entry.refreshToken.trim();
    if (refreshCache.has(refreshToken)) {
      results.push({ label: entry.label, status: 'skipped', message: 'duplicate in payload' });
      skipped += 1;
      continue;
    }
    refreshCache.add(refreshToken);

    if (await antAccountExistsByRefresh(env, refreshToken)) {
      results.push({ label: entry.label, status: 'skipped', message: 'refresh token already exists' });
      skipped += 1;
      continue;
    }

    const targetLabel = entry.label || entry.userEmail || entry.userId || `ant-${randomSuffix()}`;
    let finalLabel = sanitizeLabel(targetLabel);
    if (!finalLabel) finalLabel = `ant-${randomSuffix()}`;

    const existing = await getAntAccountByLabel(env, finalLabel);
    if (existing || labelCache[finalLabel]) {
      finalLabel = `${finalLabel}-${randomSuffix()}`;
    }

    try {
      await saveAntAccount(env, {
        ...entry,
        label: finalLabel,
      });
      labelCache[finalLabel] = true;
      created += 1;
      results.push({ label: finalLabel, status: 'created' });
    } catch (error) {
      if (error instanceof RequestError && error.message === 'label already exists') {
        results.push({ label: finalLabel, status: 'skipped', message: 'label already exists' });
        skipped += 1;
      } else {
        const message = error instanceof Error ? error.message : 'unknown error';
        results.push({ label: finalLabel, status: 'failed', message });
        failed += 1;
      }
    }
  }

  return jsonResponse({
    total: parsed.length,
    created,
    skipped,
    failed,
    results,
  });
}

type ParsedAntAccount = {
  label: string;
  userId?: string | null;
  userEmail?: string | null;
  refreshToken: string;
  accessToken?: string | null;
  expiresIn?: number | null;
  timestamp?: number | null;
  raw?: any;
};

function parseAntAccounts(input: any): ParsedAntAccount[] {
  const records: ParsedAntAccount[] = [];
  const append = (raw: any, key?: string) => {
    if (!raw) return;
    const credentialType =
      (typeof raw.credential_type === 'string' && raw.credential_type.toLowerCase()) ||
      (typeof raw.credentialType === 'string' && raw.credentialType.toLowerCase());
    if (credentialType && credentialType !== 'ant') return;

    const source = raw.content && typeof raw.content === 'object' ? raw.content : raw;
    const refreshToken =
      typeof source.refresh_token === 'string'
        ? source.refresh_token
        : typeof source.refreshToken === 'string'
          ? source.refreshToken
          : '';
    if (!refreshToken) return;
    const accessToken =
      typeof source.access_token === 'string'
        ? source.access_token
        : typeof source.accessToken === 'string'
          ? source.accessToken
          : null;
    const expiresInRaw =
      typeof source.expires_in === 'number'
        ? source.expires_in
        : typeof source.expiresIn === 'number'
          ? source.expiresIn
          : null;
    const timestamp =
      typeof source.timestamp === 'number'
        ? source.timestamp
        : typeof source.created_at === 'string'
          ? Date.parse(source.created_at)
          : typeof source.createdAt === 'string'
            ? Date.parse(source.createdAt)
            : null;
    const email =
      typeof source.user_email === 'string'
        ? source.user_email
        : typeof source.email === 'string'
          ? source.email
          : typeof raw.status?.user_email === 'string'
            ? raw.status.user_email
            : undefined;
    const userId =
      typeof source.user_id === 'string'
        ? source.user_id
        : typeof source.userId === 'string'
          ? source.userId
          : undefined;
    const label =
      typeof raw.filename === 'string'
        ? stripExtension(raw.filename)
        : typeof key === 'string'
          ? stripExtension(key)
          : email || userId || '';
    records.push({
      label: sanitizeLabel(label || ''),
      userEmail: email,
      userId,
      refreshToken,
      accessToken,
      expiresIn: expiresInRaw,
      timestamp,
      raw,
    });
  };

  if (Array.isArray(input)) {
    for (const item of input) append(item);
    return records;
  }

  if (input && typeof input === 'object') {
    if (input.creds && typeof input.creds === 'object') {
      for (const [key, value] of Object.entries(input.creds as Record<string, unknown>)) {
        append(value, key);
      }
      return records;
    }
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      append(value, key);
    }
  }
  return records;
}

async function saveAntAccount(
  env: Env,
  data: ParsedAntAccount & { label: string },
): Promise<PublicAntAccount> {
  const now = Date.now();
  const expiresIn = typeof data.expiresIn === 'number' ? data.expiresIn : 3600;
  const issuedAt = typeof data.timestamp === 'number' ? data.timestamp : now;
  const expiresAt = data.accessToken ? issuedAt + Math.max(0, expiresIn - 60) * 1000 : null;
  const id = crypto.randomUUID();
  try {
    await env.DB.prepare(
      `INSERT INTO ant_accounts
         (id, label, user_id, user_email, access_token, refresh_token, expires_in, access_token_expires_at, is_enabled, last_error, raw_json, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, NULL, ?9, ?10, ?10);`,
    )
      .bind(
        id,
        data.label,
        data.userId ?? null,
        data.userEmail ?? null,
        data.accessToken ?? null,
        data.refreshToken,
        expiresIn,
        expiresAt,
        data.raw ? JSON.stringify(data.raw) : null,
        now,
      )
      .run();
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.toLowerCase().includes('unique')) {
      throw new RequestError('label already exists', 409);
    }
    throw new RequestError(`Failed to save ant account: ${msg}`, 500);
  }
  return {
    id,
    label: data.label,
    userEmail: data.userEmail,
    userId: data.userId,
    isEnabled: true,
    createdAt: now,
    updatedAt: now,
  };
}

async function antAccountExistsByRefresh(env: Env, refreshToken: string): Promise<boolean> {
  const res = await env.DB.prepare('SELECT 1 FROM ant_accounts WHERE refresh_token = ?1 LIMIT 1;')
    .bind(refreshToken)
    .all();
  return Boolean(res.results && res.results.length);
}

async function getAntAccountByLabel(env: Env, label: string): Promise<AntAccountRecord | null> {
  const res = await env.DB.prepare('SELECT * FROM ant_accounts WHERE label = ?1 LIMIT 1;')
    .bind(label)
    .all<AntAccountRow>();
  return res.results?.[0] ?? null;
}

async function setAntEnabled(env: Env, accountId: string, enabled: boolean): Promise<void> {
  const now = Date.now();
  const res = await env.DB.prepare(
    'UPDATE ant_accounts SET is_enabled = ?1, updated_at = ?2 WHERE id = ?3;',
  )
    .bind(enabled ? 1 : 0, now, accountId)
    .run();
  if ((res as { success?: boolean }).success === false || d1Changes(res) === 0) {
    throw new RequestError('Antigravity account not found', 404);
  }
}

async function deleteAntAccount(env: Env, accountId: string): Promise<void> {
  const res = await env.DB.prepare('DELETE FROM ant_accounts WHERE id = ?1;')
    .bind(accountId)
    .run();
  if ((res as { success?: boolean }).success === false) {
    throw new RequestError('Failed to delete ant account', 500);
  }
  if (d1Changes(res) === 0) {
    throw new RequestError('Antigravity account not found', 404);
  }
}

async function exportAntAccount(env: Env, accountId: string): Promise<Record<string, unknown>> {
  const res = await env.DB.prepare('SELECT * FROM ant_accounts WHERE id = ?1 LIMIT 1;')
    .bind(accountId)
    .all<AntAccountRow>();
  const row = res.results?.[0];
  if (!row) throw new RequestError('Antigravity account not found', 404);
  if (row.raw_json) {
    try {
      return JSON.parse(row.raw_json);
    } catch {
      /* fall through */
    }
  }
  return {
    access_token: row.access_token,
    refresh_token: row.refresh_token,
    expires_in: row.expires_in,
    timestamp: row.created_at,
    user_email: row.user_email,
    user_id: row.user_id,
  };
}

async function handleAntChatCompletion(request: Request, env: Env): Promise<Response> {
  let body: any;
  try {
    body = await parseJson(request);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid JSON body';
    return googleErrorResponse(400, message);
  }
  const messages = Array.isArray(body.messages) ? body.messages : null;
  if (!messages) {
    return googleErrorResponse(400, 'messages is required');
  }
  const model =
    typeof body.model === 'string' && body.model.trim() ? body.model.trim() : 'gemini-2.0-flash-exp';
  const stream = body.stream !== false;
  const antRequest = buildAntRequestBody(messages, model, body.tools, body);

  let attempts = 0;
  let lastResponse: Response | null = null;
  while (attempts < MAX_ACCOUNT_RETRIES) {
    attempts += 1;
    const account = await getRandomActiveAntAccount(env);
    if (!account) break;
    let token: string;
    try {
      token = await getValidAntAccessToken(env, account);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to refresh token';
      lastResponse = googleErrorResponse(500, message);
      continue;
    }

    try {
      if (stream) {
        const upstream = await callAntUpstream(env, 'streamGenerateContent', antRequest, token, true);
        if (!upstream.ok || !upstream.body) {
          lastResponse = await forwardAntError(upstream, env, account.id);
          continue;
        }
        await clearAntAccountError(env, account.id);
        return await streamAntSse(upstream, model);
      }

      const upstream = await callAntUpstream(env, 'generateContent', antRequest, token);
      if (!upstream.ok) {
        lastResponse = await forwardAntError(upstream, env, account.id);
        continue;
      }
      await clearAntAccountError(env, account.id);
      const data = (await upstream.json()) as CaGenerateContentResponse;
      const mapped = antResponseToOpenAI(data, model);
      return jsonResponse(mapped);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Internal error';
      lastResponse = googleErrorResponse(500, message);
    }
  }

  if (lastResponse) return lastResponse;
  return googleErrorResponse(503, 'No active Antigravity accounts available');
}

async function handleAntModels(env: Env): Promise<Response> {
  let attempts = 0;
  let lastResponse: Response | null = null;
  while (attempts < MAX_ACCOUNT_RETRIES) {
    attempts += 1;
    const account = await getRandomActiveAntAccount(env);
    if (!account) break;
    let token: string;
    try {
      token = await getValidAntAccessToken(env, account);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to refresh token';
      lastResponse = googleErrorResponse(500, message);
      continue;
    }

    const upstream = await callAntUpstream(env, 'fetchAvailableModels', {}, token);
    if (!upstream.ok) {
      lastResponse = await forwardAntError(upstream, env, account.id);
      continue;
    }
    await clearAntAccountError(env, account.id);
    const data = (await upstream.json()) as { models?: Record<string, unknown> };
    const list = Object.keys(data.models ?? {}).map((id) => ({
      id,
      object: 'model',
      created: Math.floor(Date.now() / 1000),
      owned_by: 'google',
    }));
    return jsonResponse({ object: 'list', data: list });
  }
  if (lastResponse) return lastResponse;
  return googleErrorResponse(503, 'No active Antigravity accounts available');
}

function buildAntRequestBody(
  messages: any[],
  modelName: string,
  openaiTools?: any[],
  parameters?: Record<string, unknown>,
): Record<string, unknown> {
  const enableThinking =
    modelName.endsWith('-thinking') ||
    modelName === 'gemini-2.5-pro' ||
    modelName.startsWith('gemini-3-pro-') ||
    modelName === 'rev19-uic3-1p' ||
    modelName === 'gpt-oss-120b-medium';
  const actualModelName = modelName.endsWith('-thinking') ? modelName.slice(0, -9) : modelName;
  return {
    project: generateAntProjectId(),
    requestId: `agent-${crypto.randomUUID()}`,
    request: {
      contents: openaiMessagesToAnt(messages),
      systemInstruction: {
        role: 'user',
        parts: [{ text: ANT_DEFAULT_SYSTEM_PROMPT }],
      },
      tools: convertOpenAIToolsToAnt(openaiTools),
      toolConfig: {
        functionCallingConfig: {
          mode: 'VALIDATED',
        },
      },
      generationConfig: buildAntGenerationConfig(parameters || {}, enableThinking, actualModelName),
      sessionId: generateAntSessionId(),
    },
    model: actualModelName,
    userAgent: 'antigravity',
  };
}

function openaiMessagesToAnt(openaiMessages: any[]): Array<{ role: string; parts: any[] }> {
  const antMessages: Array<{ role: string; parts: any[] }> = [];

  const handleUser = (content: any) => {
    const extracted = extractImagesFromContent(content);
    antMessages.push({
      role: 'user',
      parts: [
        { text: extracted.text },
        ...extracted.images,
      ],
    });
  };

  const handleAssistant = (message: any) => {
    const last = antMessages[antMessages.length - 1];
    const hasToolCalls = Array.isArray(message.tool_calls) && message.tool_calls.length > 0;
    const hasContent = typeof message.content === 'string' && message.content.trim() !== '';
    const tools = hasToolCalls
      ? message.tool_calls.map((tool: any) => ({
          functionCall: {
            id: tool.id,
            name: tool.function?.name,
            args: {
              query: tool.function?.arguments,
            },
          },
        }))
      : [];

    if (last?.role === 'model' && hasToolCalls && !hasContent) {
      last.parts.push(...tools);
    } else {
      const parts: any[] = [];
      if (hasContent) parts.push({ text: message.content });
      parts.push(...tools);
      antMessages.push({ role: 'model', parts });
    }
  };

  const handleTool = (message: any) => {
    let functionName = '';
    for (let i = antMessages.length - 1; i >= 0; i--) {
      if (antMessages[i].role === 'model') {
        for (const part of antMessages[i].parts) {
          if (part.functionCall && part.functionCall.id === message.tool_call_id) {
            functionName = part.functionCall.name;
            break;
          }
        }
      }
      if (functionName) break;
    }
    const functionResponse = {
      functionResponse: {
        id: message.tool_call_id,
        name: functionName,
        response: {
          output: message.content,
        },
      },
    };
    const last = antMessages[antMessages.length - 1];
    if (last?.role === 'user' && last.parts.some((p) => p.functionResponse)) {
      last.parts.push(functionResponse);
    } else {
      antMessages.push({ role: 'user', parts: [functionResponse] });
    }
  };

  for (const message of openaiMessages) {
    if (message.role === 'user' || message.role === 'system') {
      handleUser(message.content);
    } else if (message.role === 'assistant') {
      handleAssistant(message);
    } else if (message.role === 'tool') {
      handleTool(message);
    }
  }

  return antMessages;
}

function extractImagesFromContent(
  content: any,
): { text: string; images: Array<{ inlineData: { mimeType: string; data: string } }> } {
  const result = { text: '', images: [] as Array<{ inlineData: { mimeType: string; data: string } }> };
  if (typeof content === 'string') {
    result.text = content;
    return result;
  }
  if (Array.isArray(content)) {
    for (const item of content) {
      if (item?.type === 'text') {
        result.text += item.text ?? '';
      } else if (item?.type === 'image_url') {
        const imageUrl = item.image_url?.url || '';
        const match = imageUrl.match(/^data:image\/(\w+);base64,(.+)$/);
        if (match) {
          result.images.push({
            inlineData: {
              mimeType: `image/${match[1]}`,
              data: match[2],
            },
          });
        }
      }
    }
  }
  return result;
}

function buildAntGenerationConfig(
  params: Record<string, unknown>,
  enableThinking: boolean,
  actualModelName: string,
): Record<string, unknown> {
  const config: Record<string, unknown> = {
    topP: typeof params.top_p === 'number' ? params.top_p : 0.85,
    topK: typeof params.top_k === 'number' ? params.top_k : 50,
    temperature: typeof params.temperature === 'number' ? params.temperature : 1,
    candidateCount: 1,
    maxOutputTokens: typeof params.max_tokens === 'number' ? params.max_tokens : 8096,
    stopSequences: ['<|user|>', '<|bot|>', '<|context_request|>', '<|endoftext|>', '<|end_of_turn|>'],
    thinkingConfig: {
      includeThoughts: enableThinking,
      thinkingBudget: enableThinking ? 1024 : 0,
    },
  };
  if (enableThinking && actualModelName.includes('claude')) {
    delete config.topP;
  }
  return config;
}

function convertOpenAIToolsToAnt(openaiTools: any[] | undefined): any[] {
  if (!openaiTools || !Array.isArray(openaiTools) || !openaiTools.length) return [];
  return openaiTools.map((tool) => {
    if (tool?.function?.parameters && typeof tool.function.parameters === 'object') {
      delete tool.function.parameters.$schema;
    }
    return {
      functionDeclarations: [
        {
          name: tool.function?.name,
          description: tool.function?.description,
          parameters: tool.function?.parameters,
        },
      ],
    };
  });
}

function generateAntProjectId(): string {
  const adjectives = ['useful', 'bright', 'swift', 'calm', 'bold'];
  const nouns = ['fuze', 'wave', 'spark', 'flow', 'core'];
  const randomAdj = adjectives[Math.floor(Math.random() * adjectives.length)];
  const randomNoun = nouns[Math.floor(Math.random() * nouns.length)];
  const randomNum = Math.random().toString(36).substring(2, 7);
  return `${randomAdj}-${randomNoun}-${randomNum}`;
}

function generateAntSessionId(): string {
  return String(-Math.floor(Math.random() * 9e18));
}

async function callAntUpstream(
  env: Env,
  method: string,
  payload: unknown,
  accessToken: string,
  stream = false,
): Promise<Response> {
  const base = env.CODE_ASSIST_ENDPOINT?.trim() || ANT_DEFAULT_ENDPOINT;
  const url = `${base}/v1internal:${method}${stream ? '?alt=sse' : ''}`;
  return fetchWithPrivacy(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${accessToken}`,
      'user-agent': 'antigravity-gcli2api/1.0',
      'x-goog-api-client': 'antigravity-gcli2api/1.0',
    },
    body: JSON.stringify(payload),
  });
}

async function streamAntSse(upstream: Response, model: string): Promise<Response> {
  const body = upstream.body;
  if (!body) return googleErrorResponse(500, 'Upstream stream missing body');
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const id = `chatcmpl-${crypto.randomUUID()}`;
  const created = Math.floor(Date.now() / 1000);
  let buffer = '';
  let dataBuffer: string[] = [];
  let finished = false;
  let thinkingStarted = false;
  let hasToolCall = false;
  let pendingTools: any[] = [];

  const send = async (payload: unknown) => {
    await writer.write(encoder.encode(`data: ${JSON.stringify(payload)}\n\n`));
  };

  const sendContent = async (text: string) =>
    send({
      id,
      object: 'chat.completion.chunk',
      created,
      model,
      choices: [{ index: 0, delta: { content: text }, finish_reason: null }],
    });

  const sendTools = async (tools: any[]) =>
    send({
      id,
      object: 'chat.completion.chunk',
      created,
      model,
      choices: [{ index: 0, delta: { tool_calls: tools }, finish_reason: null }],
    });

  const finalize = async (reason: 'stop' | 'tool_calls') => {
    if (thinkingStarted) {
      await sendContent('\n</think>\n');
      thinkingStarted = false;
    }
    await send({
      id,
      object: 'chat.completion.chunk',
      created,
      model,
      choices: [{ index: 0, delta: {}, finish_reason: reason }],
    });
    await writer.write(encoder.encode('data: [DONE]\n\n'));
    finished = true;
    await writer.close();
  };

  const reader = body.getReader();
  (async () => {
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          buffer += decoder.decode();
        } else if (value) {
          buffer += decoder.decode(value, { stream: true });
        }
        let idx: number;
        while ((idx = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 1);
          const trimmed = line.replace(/\r$/, '');
          if (trimmed.startsWith('data:')) {
            dataBuffer.push(trimmed.slice(5).trim());
          } else if (trimmed === '') {
            if (!dataBuffer.length) continue;
            const chunk = dataBuffer.join('\n');
            dataBuffer = [];
            if (chunk === '[DONE]') {
              await finalize(hasToolCall ? 'tool_calls' : 'stop');
              return;
            }
            try {
              const parsed = JSON.parse(chunk) as CaGenerateContentResponse;
              const candidate = parsed.response?.candidates?.[0] as any;
              const parts: any[] = candidate?.content?.parts ?? [];
              for (const part of parts) {
                if (part?.thought === true) {
                  if (!thinkingStarted) {
                    await sendContent('<think>\n');
                    thinkingStarted = true;
                  }
                  if (typeof part.text === 'string') {
                    await sendContent(part.text);
                  }
                } else if (typeof part?.text === 'string') {
                  if (thinkingStarted) {
                    await sendContent('\n</think>\n');
                    thinkingStarted = false;
                  }
                  await sendContent(part.text);
                } else if (part?.functionCall) {
                  pendingTools.push({
                    id: part.functionCall.id,
                    type: 'function',
                    function: {
                      name: part.functionCall.name,
                      arguments: JSON.stringify(part.functionCall.args ?? {}),
                    },
                  });
                }
              }
              if (candidate?.finishReason && pendingTools.length) {
                hasToolCall = true;
                await sendTools(pendingTools);
                pendingTools = [];
              }
            } catch {
              /* ignore malformed chunk */
            }
          }
        }
        if (done) break;
      }
      await finalize(hasToolCall ? 'tool_calls' : 'stop');
    } catch {
      if (!finished) {
        try {
          await finalize(hasToolCall ? 'tool_calls' : 'stop');
        } catch {
          /* ignore */
        }
      }
    } finally {
      try {
        reader.releaseLock();
      } catch {
        /* ignore */
      }
    }
  })();

  const headers = new Headers({
    'content-type': 'text/event-stream',
    'cache-control': 'no-store',
    ...corsHeaders(),
  });
  return new Response(readable, { status: 200, headers });
}

function antResponseToOpenAI(res: CaGenerateContentResponse, model: string): Record<string, unknown> {
  const candidate: any = res.response?.candidates?.[0] ?? {};
  const parts: any[] = candidate?.content?.parts ?? [];
  const textParts: string[] = [];
  const toolCalls: any[] = [];
  let thinkingStarted = false;
  for (const part of parts) {
    if (part?.thought === true) {
      if (!thinkingStarted) {
        textParts.push('<think>');
        thinkingStarted = true;
      }
      if (typeof part.text === 'string') {
        textParts.push(part.text);
      }
    } else if (typeof part?.text === 'string') {
      if (thinkingStarted) {
        textParts.push('</think>');
        thinkingStarted = false;
      }
      textParts.push(part.text);
    } else if (part?.functionCall) {
      toolCalls.push({
        id: part.functionCall.id,
        type: 'function',
        function: {
          name: part.functionCall.name,
          arguments: JSON.stringify(part.functionCall.args ?? {}),
        },
      });
    }
  }
  if (thinkingStarted) {
    textParts.push('</think>');
  }
  const finishReason = toolCalls.length ? 'tool_calls' : 'stop';
  const message: Record<string, unknown> = {
    role: 'assistant',
    content: textParts.join('\n'),
  };
  if (toolCalls.length) {
    message['tool_calls'] = toolCalls;
  }
  return {
    id: `chatcmpl-${crypto.randomUUID()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        message,
        finish_reason: finishReason,
      },
    ],
  };
}

async function getRandomActiveAntAccount(env: Env): Promise<AntAccountRecord | null> {
  try {
    const result = await env.DB.prepare(
      'SELECT * FROM ant_accounts WHERE is_enabled = 1 ORDER BY random() LIMIT 1;',
    ).all<AntAccountRow>();
    return result.results?.[0] ?? null;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to select ant account';
    throw new RequestError(
      `Failed to select ant account (check D1 binding / wrangler version): ${message}`,
      500,
    );
  }
}

async function getValidAntAccessToken(env: Env, account: AntAccountRecord): Promise<string> {
  const now = Date.now();
  if (
    account.access_token &&
    account.access_token_expires_at &&
    account.access_token_expires_at - 60_000 > now
  ) {
    return account.access_token;
  }
  return refreshAntAccessToken(env, account);
}

async function refreshAntAccessToken(env: Env, account: AntAccountRecord): Promise<string> {
  const params = new URLSearchParams();
  params.set('client_id', ANT_DEFAULT_CLIENT_ID);
  params.set('client_secret', ANT_DEFAULT_CLIENT_SECRET);
  params.set('refresh_token', account.refresh_token);
  params.set('grant_type', 'refresh_token');
  const response = await fetchWithPrivacy(DEFAULT_TOKEN_URI, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: params,
  });
  if (!response.ok) {
    const text = await response.text();
    const message = `Failed to refresh token (${response.status}): ${text || 'unknown error'}`;
    const now = Date.now();
    if (response.status === 403) {
      await env.DB.prepare(
        'UPDATE ant_accounts SET is_enabled = 0, last_error = ?1, updated_at = ?2 WHERE id = ?3;',
      )
        .bind(message.slice(0, 500), now, account.id)
        .run();
    } else {
      await env.DB.prepare(
        'UPDATE ant_accounts SET last_error = ?1, updated_at = ?2 WHERE id = ?3;',
      )
        .bind(message.slice(0, 500), now, account.id)
        .run();
    }
    throw new Error(message);
  }
  const data = (await response.json()) as { access_token?: string; expires_in?: number };
  if (!data.access_token) {
    throw new Error('No access_token returned from Google');
  }
  const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 3600;
  const expiresAt = Date.now() + (expiresIn - 60) * 1000;
  await env.DB.prepare(
    'UPDATE ant_accounts SET access_token = ?1, expires_in = ?2, access_token_expires_at = ?3, updated_at = ?4 WHERE id = ?5;',
  )
    .bind(data.access_token, expiresIn, expiresAt, Date.now(), account.id)
    .run();
  account.access_token = data.access_token;
  account.expires_in = expiresIn;
  account.access_token_expires_at = expiresAt;
  return data.access_token;
}

async function clearAntAccountError(env: Env, accountId: string): Promise<void> {
  await env.DB.prepare('UPDATE ant_accounts SET last_error = NULL, updated_at = ?1 WHERE id = ?2;')
    .bind(Date.now(), accountId)
    .run();
}

async function forwardAntError(
  upstream: Response,
  env?: Env,
  accountId?: string,
): Promise<Response> {
  const text = await upstream.text();
  let parsed: any;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
  }
  const status = upstream.status || 500;
  const message =
    parsed?.error?.message ||
    parsed?.message ||
    (typeof parsed === 'string' && parsed) ||
    text ||
    `Upstream error ${status}`;
  if (env && accountId) {
    const now = Date.now();
    const reason = message.slice(0, 500);
    if (status === 403) {
      await env.DB.prepare(
        'UPDATE ant_accounts SET is_enabled = 0, last_error = ?1, updated_at = ?2 WHERE id = ?3;',
      )
        .bind(reason, now, accountId)
        .run();
    } else {
      await env.DB.prepare(
        'UPDATE ant_accounts SET last_error = ?1, updated_at = ?2 WHERE id = ?3;',
      )
        .bind(reason, now, accountId)
        .run();
    }
  }
  return googleErrorResponse(status, message);
}
