import { Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import type { Request, Response } from "express";
import { COOKIE_MAX_AGE_MS, CookieKey, DEFAULT_COOKIE_OPTIONS } from "@repo/auth/strategies";
import type { JwtPayload } from "@repo/auth/types";
import type { StringValue } from "ms";

import type { EnvValidationType } from "../env.validation";

@Injectable()
export class AuthService {
  private readonly cookieConfig;

  constructor(
    private readonly jwtService: JwtService,
    private readonly config: ConfigService<EnvValidationType, true>,
  ) {
    this.cookieConfig = DEFAULT_COOKIE_OPTIONS;
  }

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

  extractRefreshToken(req: Request): string {
    const fromCookie = req.cookies?.[CookieKey.RefreshToken] as string | undefined;
    const fromHeader = req.headers["x-refresh-token"] as string | undefined;

    const token = fromCookie ?? fromHeader;
    if (!token) {
      throw new UnauthorizedException("Missing refresh token");
    }
    return token;
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

  setAuthCookies(
    tokens: { accessToken: string; refreshToken: string },
    response: Response,
  ): void {
    const { accessToken, refreshToken } = tokens;
    const expiry = new Date(Date.now() + COOKIE_MAX_AGE_MS);

    response.cookie(CookieKey.AccessToken, accessToken, {
      ...this.cookieConfig,
      expires: expiry,
    });
    response.cookie(CookieKey.RefreshToken, refreshToken, {
      ...this.cookieConfig,
      path: this.cookieConfig.refreshTokenPath ?? this.cookieConfig.path,
      expires: expiry,
    });
  }

  clearAuthCookies(response: Response): void {
    response.clearCookie(CookieKey.AccessToken, this.cookieConfig);
    response.clearCookie(CookieKey.RefreshToken, {
      ...this.cookieConfig,
      path: this.cookieConfig.refreshTokenPath ?? this.cookieConfig.path,
    });
  }
}