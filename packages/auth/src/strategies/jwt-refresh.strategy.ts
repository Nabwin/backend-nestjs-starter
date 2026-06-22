import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import type { Request } from "express";
import { ExtractJwt, Strategy } from "passport-jwt";

import type { JwtPayload } from "../types";
import type { EnvValidationType } from "./types";

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, "jwt-refresh") {
  constructor(config: ConfigService<EnvValidationType, true>) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => (req.body as Record<string, string>)?.refreshToken ?? null,
        (req: Request) => (req.headers["x-refresh-token"] as string) ?? null,
        (req: Request) => req?.cookies?.refresh_token ?? null,
      ]),
      ignoreExpiration: false,
      secretOrKey: config.get("JWT_REFRESH_SECRET"),
      passReqToCallback: true,
    });
  }

  validate(req: Request, payload: JwtPayload) {
    const refreshToken =
      (req.cookies?.refresh_token as string) ??
      (req.headers["x-refresh-token"] as string) ??
      (req.body as Record<string, string>)?.refreshToken;

    return { ...payload, refreshToken };
  }
}
