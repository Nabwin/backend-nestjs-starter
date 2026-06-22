import { Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import type { JwtPayload } from "@repo/auth/types";
import type { StringValue } from "ms";

import type { EnvValidationType } from "../env.validation";

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly config: ConfigService<EnvValidationType, true>,
  ) {}

  async signIn(
    email: string,
    _password: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    if (!email) {
      throw new UnauthorizedException("Invalid credentials");
    }

    const payload = {
      sub: "user-id",
      email,
      role: "user",
      sessionId: crypto.randomUUID(),
      jti: crypto.randomUUID(),
    };

    const accessToken = await this.jwtService.signAsync(payload);

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: this.config.get("JWT_REFRESH_SECRET"),
      expiresIn: this.config.get("JWT_REFRESH_EXPIRES_IN") as StringValue,
    });

    return { accessToken, refreshToken };
  }

  async refreshToken(token: string): Promise<{ accessToken: string; refreshToken: string }> {
    try {
      const payload = this.jwtService.verify<JwtPayload>(token, {
        secret: this.config.get("JWT_REFRESH_SECRET"),
      });

      const newPayload = {
        sub: payload.sub,
        email: payload.email,
        role: payload.role,
        sessionId: payload.sessionId,
        jti: crypto.randomUUID(),
      };

      const accessToken = await this.jwtService.signAsync(newPayload);
      const refreshToken = await this.jwtService.signAsync(newPayload, {
        secret: this.config.get("JWT_REFRESH_SECRET"),
        expiresIn: this.config.get("JWT_REFRESH_EXPIRES_IN") as StringValue,
      });

      return { accessToken, refreshToken };
    } catch {
      throw new UnauthorizedException("Invalid refresh token");
    }
  }

  verifyToken(token: string): JwtPayload {
    try {
      return this.jwtService.verify<JwtPayload>(token);
    } catch {
      throw new UnauthorizedException("Invalid token");
    }
  }
}
