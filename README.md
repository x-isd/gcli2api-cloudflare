# Cloudflare Worker variant

This folder contains a Cloudflare Workers build of gcli2api with:
- D1 for persistence (accounts + OAuth refresh tokens).
- Random account selection instead of lease/lock rotation.
- Password protection for every endpoint (API + admin UI).
- AI Studio-compatible auth shape (`Authorization: Bearer`, `x-goog-api-key`, or `?key=`).

## 安全警告（请勿移除）
- 二次开发时不要添加“网页直接 OAuth 登录”功能，可能导致你的 cf 账号和域名被封!!
- 不要移除这些安全提示。
- 本项目开源免费，任何收费售卖都是骗局。
- 在网页上传 JSON 凭据等同于上传密码，请仅在可信环境使用。
- 本子目录采用 PolyForm Noncommercial License，严禁商用且限制严格：禁止任何直接或间接收费、嵌入收费产品/服务或用于商业优势；使用即视为接受该协议，细则见 `LICENSE`。
- 即使你提供咸鱼代搭建依然违反了该 License, 望自重

## Quick start
1. Install deps: `npm install`.
2. Create D1: `wrangler d1 create gcli2api` and update `wrangler.toml` with the database id.
3. Apply schema: `wrangler d1 execute gcli2api --file=schema.sql`.
4. Set a strong secret (>=12 chars, not common/DEFAULT): `wrangler secret put ADMIN_PASSWORD`.
5. Dev locally: `wrangler dev`.
6. Deploy: `wrangler deploy`.

## Auth rules
- Server requires the password for **all** requests (including `/` admin UI).
- Supported credentials (any one of):
  - `Authorization: Bearer <password>` (mirrors AI Studio Bearer flow).
  - `x-goog-api-key: <password>` header.
  - `?key=<password>` query param.
- Browser users can also log in via `/login` (standalone page, no project name shown). A short-lived HttpOnly session cookie (12h) is set on success; APIs still accept the headers above.
- Weak secrets are rejected at runtime: length < 12, common weak strings, or the sample `PLEASE_CHANGE_ME`.

## Admin UI
- Served from `/` (and `/admin`), behind the same password.
- Minimal controls: list accounts, create/delete, toggle enable, update project id.
- Create accepts either explicit OAuth fields or a pasted `authorized_user.json` object.
- Per-account import/export of `authorized_user.json` (clears cached access token on import).

## Data model
- `accounts` table only (see `schema.sql`): stores label, client_id/secret, refresh_token, project_id, cached access_token, enable flag, last_error.
- Account selection uses `ORDER BY random() LIMIT 1`.

## API surface (password required)
- `GET /healthz` - basic check (password still required).
- `POST /raw/models/{model}:generateContent` and streaming/count variants (`/raw` and `/v1beta` mirror).
- `GET /api/accounts` - list (secrets omitted).
- `POST /api/accounts` - create/import credentials.
- `POST /api/accounts/bulk` - bulk import; body `{ "creds": { "filename.json": { "content": <authorized_user> } } }`.
- `PATCH /api/accounts/:id/project` - change project id.
- `PATCH /api/accounts/:id/enabled` - enable/disable.
- `DELETE /api/accounts/:id` - remove.
- `POST /api/accounts/:id/credentials/import` - replace credentials with authorized_user.json.
- `GET /api/accounts/:id/credentials/export` - download authorized_user.json for that account.

## Environment
- `ADMIN_PASSWORD` (secret, required).
- `CODE_ASSIST_ENDPOINT` (optional; defaults to `https://cloudcode-pa.googleapis.com`).
