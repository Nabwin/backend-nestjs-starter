# Backend Starter

An opinionated NestJS monorepo starter. Batteries included — auth, validation, docs, and clean tooling.

## Quick start

```sh
bun install
cp .env.example apps/api/.env
bun dev
```

That's it. Server runs on `http://localhost:3000`, Swagger at `/api-docs`.

## What's inside

| | |
|---|---|
| **Framework** | NestJS v11 |
| **Runtime** | Bun |
| **Build** | Turborepo |
| **Auth** | Passport JWT (access + refresh tokens) |
| **Validation** | Zod with ConfigService |
| **Docs** | Swagger |
| **Lint** | oxlint |
| **Format** | oxfmt |
| **Test** | Jest |

## Folder structure

```
apps/
  api/          → NestJS backend
packages/
  auth/         → @repo/auth (guards, strategies, decorators)
  typescript-config/  → shared TS configs
```

## Scripts

```sh
bun dev         # start in watch mode
bun build       # build all packages
bun test        # run tests
bun lint        # lint all packages
bun format      # format all packages
bun check-types # type-check all packages
```

## Auth

Bundled in `@repo/auth`:

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

  @Get("public")
  @Public()
  findPublic() {
    return this.usersService.findPublic();
  }
}
```

## Env

Copy `.env.example` to `apps/api/.env` and tweak:

```env
APP_ENV=development
PORT=3000
JWT_SECRET=<some-random-hex>
JWT_EXPIRES_IN=15m
JWT_REFRESH_SECRET=<some-random-hex>
JWT_REFRESH_EXPIRES_IN=7d
```