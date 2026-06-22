import { HttpStatus, Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import type { Request } from "express";
import { ExtractJwt, Strategy } from "passport-jwt";

import type { JwtPayload } from "../types";
import { CookieKey } from "./cookie-key.enum";
import type { EnvValidationType } from "./types";

const REFRESH_TOKEN_EXPIRED_CODE = "REFRESH_TOKEN_EXPIRED";

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, "jwt-refresh") {
  constructor(config: ConfigService<EnvValidationType, true>) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => (req.body as Record<string, string>)?.refreshToken ?? null,
        (req: Request) => (req.headers["x-refresh-token"] as string) ?? null,
        (req: Request) => req?.cookies?.[CookieKey.RefreshToken] ?? null,
      ]),
      ignoreExpiration: false,
      secretOrKey: config.get("JWT_REFRESH_SECRET"),
      passReqToCallback: true,
    });
  }

  handleRequest<TUser>(err: Error | null, user: TUser): TUser {
    if (err || !user) {
      if (err && err.name === "TokenExpiredError") {
        throw new UnauthorizedException({
          message: "Refresh token expired. Please login again.",
          code: REFRESH_TOKEN_EXPIRED_CODE,
          statusCode: 498,
        });
      }
      throw new UnauthorizedException("Invalid refresh token");
    }
    return user;
  }

  validate(req: Request, payload: JwtPayload) {
    const refreshToken =
      (req.cookies?.[CookieKey.RefreshToken] as string) ??
      (req.headers["x-refresh-token"] as string) ??
      (req.body as Record<string, string>)?.refreshToken;

    return { ...payload, refreshToken };
  }
}