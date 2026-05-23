# OAuth Practice

Google, GitHub, and Microsoft sign-in, written from scratch without Passport.js or NextAuth. Every step of the OAuth flow is in the code, including the parts a library would normally handle for you.

## Stack

- Frontend: Next.js (App Router) on port `3000`
- Backend: NestJS on port `4000`
- Session: 15-minute access JWT + 7-day rotating refresh token, both in `httpOnly` cookies
- Storage: in-memory maps for users and refresh tokens (hashed, never raw)
- Providers: Google (OIDC), GitHub (OAuth2), Microsoft (OIDC)

## The OAuth flow at a glance

```
Browser                Next.js (:3000)              NestJS (:4000)               Provider
   │                       │                              │                          │
   │ click "Sign in with X"│                              │                          │
   │──────────────────────►│                              │                          │
   │                       │  full-page nav to /auth/X/login                         │
   │──────────────────────────────────────────────────────►                          │
   │                                                      │  generate state cookie   │
   │                                                      │  302 redirect to provider│
   │◄─────────────────────────────────────────────────────│                          │
   │ consent screen                                                                  │
   │────────────────────────────────────────────────────────────────────────────────►│
   │                                                                                 │
   │  302 back to /auth/X/callback?code=...&state=...                                │
   │◄────────────────────────────────────────────────────────────────────────────────│
   │                                                      │  validate state          │
   │                                                      │  exchange code → tokens  │
   │                                                      │─────────────────────────►│
   │                                                      │  fetch /userinfo         │
   │                                                      │─────────────────────────►│
   │                                                      │  upsert user             │
   │                                                      │  sign session JWT        │
   │                                                      │  set httpOnly cookie     │
   │  302 to /home                                        │                          │
   │◄─────────────────────────────────────────────────────│                          │
   │                       │ /home mounts, fetch('/auth/me', credentials: 'include') │
   │                       │──────────────────────────────►                          │
   │                       │            { id, email, name, picture }                 │
   │                       │◄──────────────────────────────                          │
   │  rendered profile     │                              │                          │
   │◄──────────────────────│                              │                          │
```

## How the providers differ

The three providers mostly follow the same flow. They differ on scope names, endpoint URLs, and a few edge cases around how user info comes back.

| Concern             | Google              | GitHub                    | Microsoft                            |
| ------------------- | ------------------- | ------------------------- | ------------------------------------ |
| Protocol            | OAuth2 + OIDC       | OAuth2 only               | OAuth2 + OIDC                        |
| `id_token`          | Yes                 | No                        | Yes                                  |
| `/userinfo`         | Standard endpoint   | Custom `/user` API        | `graph.microsoft.com/oidc/userinfo`  |
| Email guaranteed?   | Yes                 | No (needs `/user/emails`) | Sometimes (personal accts)           |
| Picture in claims?  | Yes                 | Yes                       | No                                   |
| Tenant concept?     | No                  | No                        | Yes (`common` / GUID)                |
| Stable user ID      | `sub`               | `id` (number)             | `sub`                                |

## Setup

### 1. Register OAuth apps

| Provider  | Where to register                                                                 | Redirect URI                                  |
| --------- | --------------------------------------------------------------------------------- | --------------------------------------------- |
| Google    | https://console.cloud.google.com/apis/credentials                                 | `http://localhost:4000/auth/google/callback`    |
| GitHub    | https://github.com/settings/developers                                            | `http://localhost:4000/auth/github/callback`    |
| Microsoft | https://entra.microsoft.com → App registrations (multitenant + personal accounts) | `http://localhost:4000/auth/microsoft/callback` |

For each, copy the Client ID and Client Secret.

### 2. Configure environment

```bash
cp backend/.env.example backend/.env
cp frontend/.env.local.example frontend/.env.local
```

Fill in `backend/.env` with the credentials from step 1. Generate a strong `JWT_SECRET`:

```bash
openssl rand -base64 32
```

### 3. Install and run

```bash
# Backend
cd backend
npm install
npm run start:dev    # listens on :4000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev          # listens on :3000
```

Open <http://localhost:3000> and click any of the three buttons.

## Security defenses

| #   | Defense                              | Where in code                                | What it stops                          |
| --- | ------------------------------------ | -------------------------------------------- | -------------------------------------- |
| 1   | Per-provider `state` cookie          | `auth.controller.ts` login + callback        | Login CSRF and session fixation        |
| 2   | `client_secret` only on backend      | `.env`, used only in `exchange*ForTokens()`  | App impersonation                      |
| 3   | `httpOnly` cookies                   | both `oauth_state_*` and `session`           | XSS reading the session                |
| 4   | `sameSite: 'lax'`                    | all cookies                                  | General CSRF                           |
| 5   | JWT signature and expiry checks      | `jwt-auth.guard.ts`                          | Forged or expired session tokens       |
| 6   | Live user lookup (not blind on JWT)  | `users.findById(payload.sub)` in guard       | Stale data and revoked users           |
| 7   | Explicit CORS allowlist with creds   | `main.ts`                                    | Other sites reading the API with cookies |
| 8   | Short-lived access + rotating refresh| `auth.service.ts`, `refresh-tokens.store.ts` | Long-lived bearer token leaks          |
| 9   | Refresh token reuse detection        | `rotateRefreshToken` in `auth.service.ts`    | Replayed refresh tokens                |
| 10  | Hashed refresh tokens at rest        | `RefreshTokensStore.hash`                    | Store dump exposing valid tokens       |
| 11  | Path-scoped refresh cookie           | `REFRESH_COOKIE_OPTS` in `auth.controller.ts`| Refresh token surfacing on non-auth requests |

## File map

```
backend/
├── src/
│   ├── main.ts                 ← bootstrap, CORS, cookie-parser
│   ├── app.module.ts           ← global ConfigModule
│   └── auth/
│       ├── auth.module.ts      ← wires JwtModule, AuthService, guard
│       ├── auth.controller.ts  ← /auth/{google,github,microsoft}/{login,callback}, /auth/me, /auth/logout, /auth/refresh
│       ├── auth.service.ts     ← buildXAuthUrl, exchangeXCodeForTokens, fetchXUserInfo, refresh-token issue/rotate
│       ├── jwt-auth.guard.ts   ← reads session cookie, verifies JWT, looks up live user
│       ├── users.store.ts      ← in-memory Map keyed by `${provider}:${providerId}`
│       └── refresh-tokens.store.ts ← in-memory Map of SHA-256(token) → { userId, familyId, expiresAt, usedAt }
└── .env.example

frontend/
├── app/
│   ├── page.tsx                ← redirect to /login
│   ├── login/page.tsx          ← three sign-in buttons
│   ├── home/page.tsx           ← fetches /auth/me via apiFetch, renders profile
│   └── lib/
│       └── api.ts              ← apiFetch wrapper: on 401, POSTs /auth/refresh once then retries
└── .env.local.example
```

## Session model

A successful login sets two cookies:

- A 15-minute access JWT in `session`, sent on every request.
- A 7-day opaque refresh token in `refresh_token`, sent only on `/auth/*` paths.

When a request returns 401, the frontend's `apiFetch` helper POSTs `/auth/refresh` once and retries the original request. The page only sees a 401 if the refresh itself fails. Concurrent requests share a single refresh call, so an expired access token never triggers more than one `/auth/refresh`.

Each refresh mints a new token and marks the old one used. Presenting an already-used refresh token revokes every token in its family. Either the legitimate user is unlucky and has to sign in again, or someone is replaying a stolen token and gets locked out. Both outcomes are fine.

## Known limitations

Storage is in-memory. `UsersStore` and `RefreshTokensStore` are both `Map`-based and reset on backend restart. Swap them for Prisma or TypeORM to persist across restarts.

Account linking is not handled. Signing in with Google and GitHub using the same email creates two separate records. Linking them safely is its own design problem (search "OAuth account linking attack" for the relevant background).

Cookies set `secure: false` so they work over plain HTTP on `localhost`. Switch to `secure: true` once the app runs behind HTTPS.

PKCE is not implemented. The current OAuth spec recommends it for every client, including confidential ones.
