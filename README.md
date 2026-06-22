# Backend Starter

Opinionated NestJS monorepo starter. Auth, OAuth, DB, and clean tooling.

## Quick start

```sh
bun install
cp apps/api/.env.example apps/api/.env   # edit .env with your values
bun db:setup    # create DB + run migrations + seed
bun dev
```

Server at `http://localhost:3000`, Swagger at `/api-docs`.

## What's inside

| | |
|---|---|
| Framework | NestJS v11 |
| Runtime | Bun |
| Build | SWC + Turborepo |
| DB | PostgreSQL 17 + Prisma v7 |
| Cache | Redis (ioredis) |
| Auth | Passport JWT + OAuth (Google, Facebook, LinkedIn, Apple) |
| Sessions | Redis-based with refresh token rotation |
| Validation | Zod + ConfigService |
| Lint | oxlint |
| Format | oxfmt |

## Folder structure

```
apps/
  api/              → NestJS backend
packages/
  auth/             → @repo/auth (guards, strategies, decorators)
  typescript-config/ → shared TS configs
```

## Scripts

```sh
bun dev           # start in watch mode with type-checking
bun build         # build all packages
bun test          # run tests
bun lint          # lint all packages
bun format        # format all packages
bun check-types   # type-check all packages
bun db:seed       # seed roles + users
```

## Database

```sh
# First time: create migration + apply it
bunx prisma migrate dev --create-only --name create_tables
bunx prisma migrate deploy

# Apply new migrations after schema changes
bunx prisma migrate dev --create-only --name your_change
bunx prisma migrate deploy

# Seed roles (Admin, User) and test accounts
bun db:seed
```

Test accounts after seeding:

| Email | Password | Role |
|---|---|---|
| admin@example.com | password123 | Admin |
| user@example.com | password123 | User |

## Auth

Bundle in `@repo/auth`:

- `JwtAuthGuard` — protect routes
- `OptionalJwtAuthGuard` — optional auth
- `RoleGuard` + `@AllowedRoles()` — RBAC
- `@Public()` — skip auth
- `@GetCurrentUser()` / `@GetCurrentUserId()` — extract user from token

```ts
import { JwtAuthGuard, Public, GetCurrentUser } from "@repo/auth";

@Controller("users")
export class UsersController {
  @Get()
  @UseGuards(JwtAuthGuard)
  findAll(@GetCurrentUser() user: JwtPayload) {
    return this.usersService.findAll();
  }
}
```

### API endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/register` | No | Create account |
| POST | `/api/v1/auth/login/web` | No | Login (httpOnly cookie) |
| POST | `/api/v1/auth/login/mobile` | No | Login (refresh token in body) |
| POST | `/api/v1/auth/refresh` | No | Rotate refresh token (cookie) |
| POST | `/api/v1/auth/refresh/mobile` | No | Rotate refresh token (body) |
| POST | `/api/v1/auth/logout` | Yes | Logout + clear session (cookie) |
| POST | `/api/v1/auth/logout/mobile` | Yes | Logout + clear session (body) |
| GET | `/api/v1/auth/me` | Yes | Current user profile |
| GET | `/api/v1/auth/check-auth` | Yes | Check if authenticated |
| GET | `/api/v1/auth/sessions` | Yes | List active sessions |
| DELETE | `/api/v1/auth/sessions/:id` | Yes | Revoke a session |

### OAuth

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/oauth/google` | Google login |
| GET | `/api/v1/oauth/google/callback` | Google callback |
| GET | `/api/v1/oauth/facebook` | Facebook login |
| GET | `/api/v1/oauth/facebook/callback` | Facebook callback |
| GET | `/api/v1/oauth/linkedin` | LinkedIn login |
| GET | `/api/v1/oauth/linkedin/callback` | LinkedIn callback |
| GET | `/api/v1/oauth/apple` | Apple login (web) |
| POST | `/api/v1/oauth/apple/callback` | Apple callback (web) |
| POST | `/api/v1/oauth/apple/mobile/callback` | Apple login (mobile) |

Toggle providers via `.env`:

```env
ENABLED_OAUTH_METHODS='google,facebook'
```

## Env reference

```env
PORT=3000
APP_ENV=development
DATABASE_URL='postgresql://user:pass@localhost:5432/dbname'
REDIS_URL='redis://localhost:6379'
REDIS_NAMESPACE='app-dev'

JWT_SECRET='your-jwt-secret'
JWT_EXPIRES_IN=15m
JWT_REFRESH_SECRET='your-refresh-secret'
JWT_REFRESH_EXPIRES_IN=7d

ENABLED_OAUTH_METHODS='google,facebook,linkedin'
GOOGLE_CLIENT_ID=''
GOOGLE_CLIENT_SECRET=''
GOOGLE_CALLBACK_URL=''
FACEBOOK_CLIENT_ID=''
FACEBOOK_CLIENT_SECRET=''
FACEBOOK_CALLBACK_URL=''
LINKEDIN_CLIENT_ID=''
LINKEDIN_CLIENT_SECRET=''
LINKEDIN_CALLBACK_URL=''
APPLE_CLIENT_ID=''
APPLE_TEAM_ID=''
APPLE_KEY_ID=''
APPLE_PRIVATE_KEY_PATH=''
APPLE_CALLBACK_URL=''
APPLE_MOBILE_CLIENT_ID=''
```

## Env validation

All env vars are validated at startup with Zod. Invalid values (typos in `ENABLED_OAUTH_METHODS`, missing required vars) crash the app with a clear error message before the server starts.