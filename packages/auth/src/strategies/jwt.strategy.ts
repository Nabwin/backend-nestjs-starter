import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import type { Request } from "express";
import { ExtractJwt, Strategy } from "passport-jwt";

import type { JwtPayload } from "../types";
import type { EnvValidationType } from "./types";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, "jwt") {
  constructor(config: ConfigService<EnvValidationType, true>) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        (req: Request) => req?.cookies?.access_token ?? null,
      ]),
      ignoreExpiration: false,
      secretOrKey: config.get("JWT_SECRET"),
    });
  }

  validate(payload: JwtPayload): JwtPayload {
    return payload;
  }
}
