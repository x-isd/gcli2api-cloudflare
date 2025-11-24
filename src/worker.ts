/* Cloudflare Worker implementation of gcli2api with D1 + password protection. */

interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string;
  CODE_ASSIST_ENDPOINT?: string;
  ASSETS: Fetcher;
}

const DEFAULT_TOKEN_URI = 'https://oauth2.googleapis.com/token';
const DEFAULT_SAMPLE_PASSWORD = 'PLEASE_CHANGE_ME';
const MIN_PASSWORD_LENGTH = 12;
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

    if (!isAuthorized(request, env.ADMIN_PASSWORD)) {
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
  if (auth?.startsWith('Basic ')) {
    const raw = atob(auth.slice('Basic '.length));
    const [, password = raw] = raw.split(':');
    return password || raw;
  }
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

function isAuthorized(request: Request, secret: string): boolean {
  const provided = extractPassword(request);
  if (!provided) return false;
  return timingSafeEqual(provided, secret.trim());
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
    extraHeaders: { 'WWW-Authenticate': 'Basic realm="gcli2api", charset="UTF-8"' },
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

async function serveAsset(request: Request, env: Env): Promise<Response> {
  const assetResponse = await env.ASSETS.fetch(request);
  const headers = new Headers(assetResponse.headers);
  headers.set('cache-control', 'no-store');
  for (const [key, value] of Object.entries(corsHeaders())) {
    headers.set(key, value);
  }
  return new Response(assetResponse.body, { status: assetResponse.status, headers });
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
  const now = Date.now();

  let credentials: {
    clientId: string;
    clientSecret: string;
    refreshToken: string;
    tokenUri?: string;
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
  const effectiveProject = projectId || credentials?.projectId?.trim();
  if (!effectiveProject) return googleErrorResponse(400, 'projectId is required');
  if (!credentials) return googleErrorResponse(400, 'Missing credentials');

  const id = crypto.randomUUID();
  const tokenUri = credentials?.tokenUri ?? DEFAULT_TOKEN_URI;
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
        effectiveProject,
        1,
        now,
        now,
      )
      .run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('UNIQUE') || message.includes('unique')) {
      return googleErrorResponse(400, 'label already exists');
    }
    return googleErrorResponse(500, 'Failed to save account');
  }

  return jsonResponse({
    account: {
      id,
      label,
      projectId: effectiveProject,
      isEnabled: true,
      createdAt: now,
      updatedAt: now,
    } satisfies PublicAccount,
  });
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
  const clientId = typeof record['client_id'] === 'string' ? record['client_id'] : '';
  const clientSecret = typeof record['client_secret'] === 'string' ? record['client_secret'] : '';
  const refreshToken =
    typeof record['refresh_token'] === 'string' ? record['refresh_token'] : '';
  const projectId =
    typeof record['project_id'] === 'string'
      ? record['project_id']
      : typeof record['projectId'] === 'string'
        ? (record['projectId'] as string)
        : undefined;
  const tokenUri =
    typeof record['token_uri'] === 'string'
      ? record['token_uri']
      : typeof record['tokenUri'] === 'string'
      ? (record['tokenUri'] as string)
      : undefined;
  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error('authorizedUser is missing required fields');
  }
  return { clientId, clientSecret, refreshToken, projectId, tokenUri };
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
  if ((res as { success?: boolean }).success === false || res.changes === 0) {
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
  if ((res as { success?: boolean }).success === false || res.changes === 0) {
    throw new RequestError('Account not found', 404);
  }
}

async function deleteAccount(env: Env, accountId: string): Promise<void> {
  const res = await env.DB.prepare('DELETE FROM accounts WHERE id = ?1;').bind(accountId).run();
  if ((res as { success?: boolean }).success === false) {
    throw new RequestError('Failed to delete account', 500);
  }
  if ((res as { changes?: number }).changes === 0) {
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
  if ((res as { success?: boolean }).success === false || res.changes === 0) {
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

  const account = await getRandomActiveAccount(env);
  if (!account) return googleErrorResponse(503, 'No active accounts available');
  if (!account.project_id) return googleErrorResponse(400, 'Account is missing project_id');

  const token = await getValidAccessToken(env, account);

  try {
    if (route.method === 'generateContent') {
      let body: any;
      try {
        body = await parseJson(request);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid JSON body';
        return googleErrorResponse(400, message);
      }
      const normalized = normalizeGenerateContentRequest(body, route.model);
      const caRequest = toGenerateContentRequest(normalized, account.project_id);
      const upstream = await callUpstream(env, 'generateContent', caRequest, token);
      if (!upstream.ok) {
        return await forwardErrorResponse(upstream, env, account.id);
      }
      await clearAccountError(env, account.id);
      const data = (await upstream.json()) as CaGenerateContentResponse;
      return jsonResponse(fromGenerateContentResponse(data));
    }

    if (route.method === 'countTokens') {
      let body: any;
      try {
        body = await parseJson(request);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid JSON body';
        return googleErrorResponse(400, message);
      }
      const normalized = normalizeCountTokensRequest(body, route.model);
      const caRequest = toCountTokenRequest(normalized);
      const upstream = await callUpstream(env, 'countTokens', caRequest, token);
      if (!upstream.ok) {
        return await forwardErrorResponse(upstream, env, account.id);
      }
      await clearAccountError(env, account.id);
      const data = (await upstream.json()) as CaCountTokenResponse;
      return jsonResponse(fromCountTokenResponse(data));
    }

    if (route.method === 'streamGenerateContent') {
      let body: any;
      try {
        body = await parseJson(request);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid JSON body';
        return googleErrorResponse(400, message);
      }
      const normalized = normalizeGenerateContentRequest(body, route.model);
      const caRequest = toGenerateContentRequest(normalized, account.project_id);
      const upstream = await callUpstream(env, 'streamGenerateContent', caRequest, token, true);
      if (!upstream.ok || !upstream.body) {
        return await forwardErrorResponse(upstream, env, account.id);
      }
      await clearAccountError(env, account.id);
      return await transformSseStream(upstream, fromGenerateContentResponse);
    }
  } catch (error) {
    if (error instanceof RequestError) {
      return googleErrorResponse(error.status, error.message);
    }
    const message = error instanceof Error ? error.message : 'Internal error';
    return googleErrorResponse(500, message);
  }

  return googleErrorResponse(404, 'Unsupported method');
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
    await env.DB.prepare('UPDATE accounts SET last_error = ?1, updated_at = ?2 WHERE id = ?3;')
      .bind(message.slice(0, 500), Date.now(), accountId)
      .run();
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
  const response = await fetch(tokenUri, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: params,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to refresh token (${response.status}): ${text || 'unknown error'}`);
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
  return {
    contents: toContents(req.contents),
    systemInstruction: maybeToContent(req.config?.systemInstruction),
    cachedContent: req.config?.cachedContent,
    tools: req.config?.tools,
    toolConfig: req.config?.toolConfig,
    labels: req.config?.labels,
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
  return fetch(url, {
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
