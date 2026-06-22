import * as crypto from "crypto";

import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  UnauthorizedException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcrypt";
import type { Request, Response } from "express";
import type { StringValue } from "ms";
import ms from "ms";

import { PrismaService } from "../db/prisma.service";
import type { EnvValidationType } from "../env.validation";
import { SessionManagerService } from "../redis/session-manager.service";
import { UserStatus } from "../db/generated/enums";

const SALT_ROUNDS = 12;
const TOKEN_ID_BYTES = 32;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_ATTEMPT_WINDOW_SECONDS = 900;
const MAX_IP_ATTEMPTS_PER_MINUTE = 20;
const BLACKLIST_FALLBACK_TTL_SECONDS = 900;

interface DecodedRefreshToken {
  sub: string;
  email: string;
  role: string;
  sessionId: string;
  type: "refresh";
  rti: string;
  jti?: string;
  exp?: number;
  deviceType?: "web" | "mobile";
}

interface CreateAuthSessionOptions {
  userId: string;
  email: string;
  role: string;
  ip?: string;
  userAgent?: string;
  deviceType: "web" | "mobile";
}

export interface Tokens {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService<EnvValidationType, true>,
    private readonly sessionManager: SessionManagerService,
  ) {}

  setAuthCookies(res: Response, tokens: Tokens): void {
    const env = this.config.get("APP_ENV");
    const isSecure = env === "production";

    res.cookie("access_token", tokens.accessToken, {
      httpOnly: true,
      secure: isSecure,
      sameSite: "lax",
      path: "/",
      maxAge: ms(this.config.get("JWT_EXPIRES_IN") as StringValue),
    });
    res.cookie("refresh_token", tokens.refreshToken, {
      httpOnly: true,
      secure: isSecure,
      sameSite: "lax",
      path: "/api/v1/auth/refresh",
      maxAge: ms(this.config.get("JWT_REFRESH_EXPIRES_IN") as StringValue),
    });
  }

  clearAuthCookies(res: Response): void {
    res.clearCookie("access_token", { path: "/" });
    res.clearCookie("refresh_token", { path: "/api/v1/auth/refresh" });
  }

  getClientIp(req: Request): string {
    const forwarded = req.headers["x-forwarded-for"];
    if (typeof forwarded === "string") {
      return forwarded.split(",")[0]?.trim() ?? "unknown";
    }
    return req.ip ?? req.socket.remoteAddress ?? "unknown";
  }

  async userLoginWeb(
    user: { id: string; email: string; role: string },
    res: Response,
    binding?: { ip?: string; userAgent?: string },
  ) {
    const tokens = await this.createAuthSession({
      userId: user.id,
      email: user.email,
      role: user.role,
      ip: binding?.ip,
      userAgent: binding?.userAgent,
      deviceType: "web",
    });
    this.setAuthCookies(res, tokens);
  }

  async userLoginMobile(
    user: { id: string; email: string; role: string },
    binding?: { ip?: string; userAgent?: string },
  ): Promise<Tokens> {
    return this.createAuthSession({
      userId: user.id,
      email: user.email,
      role: user.role,
      ip: binding?.ip,
      userAgent: binding?.userAgent,
      deviceType: "mobile",
    });
  }

  async signUp(
    email: string,
    password: string,
    fullName?: string,
    ip?: string,
    userAgent?: string,
  ): Promise<Tokens> {
    const existing = await this.prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new BadRequestException("Email already taken");
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        fullName: fullName ?? null,
      },
    });

    return this.createAuthSession({
      userId: user.id,
      email,
      role: "user",
      ip,
      userAgent,
      deviceType: "web",
    });
  }

  async signIn(
    email: string,
    password: string,
    ip?: string,
    userAgent?: string,
    deviceType: "web" | "mobile" = "web",
  ): Promise<Tokens & { role: string }> {
    await this.assertLoginRateLimit(email, ip || "unknown");

    const user = await this.prisma.user.findUnique({
      where: { email },
      include: { role: true },
    });

    if (!user) {
      await this.trackFailedLogin(email);
      throw new HttpException("Invalid credentials", HttpStatus.UNAUTHORIZED);
    }

    if (user.status !== UserStatus.ACTIVE) {
      throw new ForbiddenException("Account is suspended or banned");
    }

    if (!user.password) {
      throw new BadRequestException("Please complete signup first");
    }

    const pwMatches = await bcrypt.compare(password, user.password);
    if (!pwMatches) {
      await this.trackFailedLogin(email);
      throw new HttpException("Invalid credentials", HttpStatus.UNAUTHORIZED);
    }

    const roleSlug = user.role?.slug ?? "user";
    const tokens = await this.createAuthSession({
      userId: user.id,
      email,
      role: roleSlug,
      ip,
      userAgent,
      deviceType,
    });

    await this.sessionManager.clearLoginAttempts(email);

    return { ...tokens, role: roleSlug };
  }

  async refreshToken(token: string, ip?: string, userAgent?: string): Promise<Tokens> {
    if (!token) {
      throw new UnauthorizedException("Invalid refresh token");
    }

    let decodedToken: DecodedRefreshToken;
    try {
      decodedToken = this.jwt.verify<DecodedRefreshToken>(token, {
        secret: this.config.getOrThrow("JWT_REFRESH_SECRET"),
      });
    } catch {
      throw new UnauthorizedException("Invalid refresh token");
    }

    const { sub: userId, email, role, sessionId, rti, deviceType } = decodedToken;

    if (!sessionId || !rti) {
      throw new UnauthorizedException("Invalid token format");
    }

    const refreshTokenIdHash = this.hashToken(rti);

    const sessionData = await this.sessionManager.validateSession(sessionId);
    if (!sessionData || sessionData.userId !== userId || sessionData.role !== role) {
      throw new UnauthorizedException("Session invalid or expired");
    }

    const refreshData = await this.sessionManager.getRefreshTokenData(refreshTokenIdHash);
    if (!refreshData) {
      await this.sessionManager.revokeAllSessions(userId);
      await this.prisma.refreshToken.deleteMany({ where: { userId } });
      throw new UnauthorizedException("Refresh token reuse detected. All sessions revoked.");
    }

    if (refreshData.userId !== userId || refreshData.sessionId !== sessionId) {
      await this.sessionManager.revokeSession(sessionId);
      throw new UnauthorizedException("Invalid refresh token context");
    }

    const hashedJwt = this.hashToken(token);
    const dbToken = await this.prisma.refreshToken.findFirst({
      where: { userId, token: hashedJwt },
    });
    if (!dbToken) {
      await this.sessionManager.revokeAllSessions(userId);
      await this.prisma.refreshToken.deleteMany({ where: { userId } });
      throw new UnauthorizedException("Refresh token reuse detected. All sessions revoked.");
    }

    if (ip && refreshData.ip && refreshData.ip !== ip) {
      this.logger.warn(
        `IP change detected for user=${userId} session=${sessionId}: ${refreshData.ip} -> ${ip}`,
      );
    }
    if (userAgent && refreshData.userAgent && refreshData.userAgent !== userAgent) {
      this.logger.warn(`UserAgent change detected for user=${userId} session=${sessionId}`);
    }

    const refreshTokenExpiry = this.config.get<string>("JWT_REFRESH_EXPIRES_IN");
    const refreshTokenExpirySeconds = ms(refreshTokenExpiry as StringValue) / 1000;

    const newRefreshTokenId = this.generateTokenId();
    const newRefreshTokenIdHash = this.hashToken(newRefreshTokenId);

    await this.sessionManager.rotateRefreshToken(
      refreshTokenIdHash,
      newRefreshTokenIdHash,
      refreshTokenExpirySeconds,
      ip || "unknown",
      userAgent,
    );

    await this.prisma.refreshToken.deleteMany({
      where: { userId, token: hashedJwt },
    });

    const newAccessToken = await this.jwt.signAsync(
      { sub: userId, email, role, sessionId, deviceType, jti: this.generateTokenId() },
      {
        expiresIn: this.config.get("JWT_EXPIRES_IN") as StringValue,
        secret: this.config.get("JWT_SECRET"),
      },
    );

    const newRefreshPayload = {
      sub: userId,
      email,
      role,
      sessionId,
      type: "refresh" as const,
      deviceType,
      rti: newRefreshTokenId,
      jti: this.generateTokenId(),
    };
    const newRefreshToken = await this.jwt.signAsync(newRefreshPayload, {
      expiresIn: refreshTokenExpiry as StringValue,
      secret: this.config.getOrThrow("JWT_REFRESH_SECRET"),
    });

    await this.storeRefreshTokenInDb(userId, this.hashToken(newRefreshToken));

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  async logout(
    userId: string,
    sessionId?: string,
    accessJti?: string,
    accessExp?: number,
  ): Promise<void> {
    if (sessionId) {
      const refreshTokenHash = await this.sessionManager.getSessionRefreshTokenHash(sessionId);
      await this.sessionManager.revokeSession(sessionId);
      if (refreshTokenHash) {
        await this.prisma.refreshToken.deleteMany({
          where: { userId, token: refreshTokenHash },
        });
      }
    } else {
      await this.sessionManager.revokeAllSessions(userId);
      await this.prisma.refreshToken.deleteMany({ where: { userId } });
    }

    await this.blacklistAccessTokenJti(accessJti, accessExp);
  }

  async listSessions(userId: string, currentSessionId?: string) {
    const sessionIds = await this.sessionManager.getUserSessions(userId);

    const results = await Promise.all(
      sessionIds.map(async (sessionId) => {
        const sessionData = await this.sessionManager.validateSession(sessionId);
        if (!sessionData) return null;
        return {
          sessionId,
          ip: sessionData.ip,
          userAgent: sessionData.userAgent ?? null,
          createdAt: sessionData.createdAt,
          lastUsed: sessionData.lastUsed,
          isCurrent: currentSessionId ? sessionId === currentSessionId : false,
        };
      }),
    );

    const sessions = results.filter(Boolean) as Array<{
      sessionId: string;
      ip: string;
      userAgent: string | null;
      createdAt: number;
      lastUsed: number;
      isCurrent: boolean;
    }>;

    return sessions.toSorted((a, b) => b.createdAt - a.createdAt);
  }

  async revokeSession(userId: string, sessionId: string): Promise<void> {
    const refreshTokenHash = await this.sessionManager.getSessionRefreshTokenHash(sessionId);
    await this.sessionManager.revokeSession(sessionId);
    if (refreshTokenHash) {
      await this.prisma.refreshToken.deleteMany({
        where: { userId, token: refreshTokenHash },
      });
    }
  }

  async getMe(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { role: true },
    });

    if (!user) {
      throw new BadRequestException("User not found");
    }

    return {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      avatar: user.avatar,
      role: user.role?.name ?? user.role?.slug ?? "user",
      permissions: user.role?.permissions ?? [],
      createdAt: user.createdAt,
    };
  }

  private async createAuthSession(options: CreateAuthSessionOptions): Promise<Tokens> {
    const { userId, email, role, ip, userAgent, deviceType } = options;

    const secretAT = this.config.get<string>("JWT_SECRET");
    const secretRT = this.config.getOrThrow<string>("JWT_REFRESH_SECRET");
    const accessExpiry = this.config.get("JWT_EXPIRES_IN");
    const refreshExpiry = this.config.get("JWT_REFRESH_EXPIRES_IN");
    const accessJti = this.generateTokenId();
    const refreshTokenId = this.generateTokenId();

    const sessionId = await this.sessionManager.createSession(
      userId,
      role,
      ip || "unknown",
      ms(refreshExpiry as StringValue) / 1000,
      userAgent,
    );

    const [accessToken, refreshToken] = await Promise.all([
      this.jwt.signAsync(
        { sub: userId, email, role, sessionId, deviceType, jti: accessJti },
        { expiresIn: accessExpiry as StringValue, secret: secretAT },
      ),
      this.jwt.signAsync(
        {
          sub: userId,
          email,
          role,
          sessionId,
          type: "refresh",
          deviceType,
          rti: refreshTokenId,
          jti: this.generateTokenId(),
        },
        { expiresIn: refreshExpiry as StringValue, secret: secretRT },
      ),
    ]);

    const refreshTokenIdHash = this.hashToken(refreshTokenId);

    await Promise.all([
      this.sessionManager.storeRefreshToken(
        refreshTokenIdHash,
        userId,
        sessionId,
        ms(refreshExpiry as StringValue) / 1000,
        ip || "unknown",
        userAgent,
      ),
      this.storeRefreshTokenInDb(userId, this.hashToken(refreshToken)),
    ]);

    return { accessToken, refreshToken };
  }

  private async storeRefreshTokenInDb(userId: string, refreshTokenHash: string): Promise<void> {
    const refreshExpiry = this.config.get<string>("JWT_REFRESH_EXPIRES_IN");
    const expiresInMs = ms(refreshExpiry as StringValue);
    const expiresAt = new Date(Date.now() + expiresInMs);

    const existing = await this.prisma.refreshToken.findFirst({
      where: { token: refreshTokenHash },
    });

    if (existing) {
      await this.prisma.refreshToken.update({
        where: { id: existing.id },
        data: { userId, token: refreshTokenHash, expiresAt },
      });
    } else {
      await this.prisma.refreshToken.create({
        data: { userId, token: refreshTokenHash, expiresAt },
      });
    }
  }

  private async blacklistAccessTokenJti(jti?: string, exp?: number): Promise<void> {
    if (!jti) return;
    const nowSeconds = Math.floor(Date.now() / 1000);
    const ttlSeconds = exp && exp > nowSeconds ? exp - nowSeconds : BLACKLIST_FALLBACK_TTL_SECONDS;
    await this.sessionManager.blacklistJti(jti, ttlSeconds);
  }

  private async assertLoginRateLimit(identifier: string, ip: string): Promise<void> {
    const [identifierAttempts, ipAttempts] = await Promise.all([
      this.sessionManager.getLoginAttempts(identifier),
      this.sessionManager.registerIpAttempt(ip, LOGIN_ATTEMPT_WINDOW_SECONDS),
    ]);

    if (identifierAttempts >= MAX_LOGIN_ATTEMPTS || ipAttempts > MAX_IP_ATTEMPTS_PER_MINUTE) {
      throw new HttpException(
        "Too many login attempts. Please try again later.",
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  private async trackFailedLogin(identifier: string): Promise<void> {
    await this.sessionManager.incrementLoginAttempts(identifier);
  }

  private hashToken(token: string): string {
    return crypto.createHash("sha256").update(token).digest("hex");
  }

  private generateTokenId(): string {
    return crypto.randomBytes(TOKEN_ID_BYTES).toString("hex");
  }
}
