import { InjectRedis } from "@nestjs-modules/ioredis";
import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { randomBytes } from "crypto";
import type { StringValue } from "ms";
import ms from "ms";
import type Redis from "ioredis";

import type { EnvValidationType } from "../env.validation";

interface SessionData {
  userId: string;
  role: string;
  ip: string;
  userAgent?: string;
  createdAt: number;
  lastUsed: number;
}

interface RefreshTokenData {
  userId: string;
  sessionId: string;
  ip: string;
  userAgent?: string;
  createdAt: number;
}

@Injectable()
export class SessionManagerService {
  private readonly logger = new Logger(SessionManagerService.name);
  private readonly SESSION_PREFIX = "session:";
  private readonly USER_SESSIONS_PREFIX = "user_sessions:";
  private readonly SESSION_REFRESH_PREFIX = "session_refresh:";
  private readonly REFRESH_PREFIX = "refresh:";
  private readonly BLACKLIST_PREFIX = "blacklist:";
  private readonly LOGIN_ATTEMPTS_PREFIX = "login_attempts:";
  private readonly RATE_LIMIT_PREFIX = "rate_limit:";

  constructor(
    private config: ConfigService<EnvValidationType, true>,
    @InjectRedis() private redis: Redis,
  ) {}

  async createSession(
    userId: string,
    role: string,
    ip: string,
    ttlSeconds?: number,
    userAgent?: string,
  ): Promise<string> {
    const sessionId = this.generateSessionId();
    const now = Date.now();

    const refreshExpiry = this.config.get<string>("JWT_REFRESH_EXPIRES_IN") || "7d";
    const defaultTTL = Math.floor(ms(refreshExpiry as StringValue) / 1000);
    const sessionTTL = ttlSeconds || defaultTTL;

    const sessionData: SessionData = {
      userId,
      role,
      ip,
      userAgent,
      createdAt: now,
      lastUsed: now,
    };

    await this.redis.setex(
      `${this.SESSION_PREFIX}${sessionId}`,
      sessionTTL,
      JSON.stringify(sessionData),
    );

    await this.addToUserSessions(userId, sessionId, sessionTTL);

    this.logger.debug(`Created session ${sessionId} for user ${userId}`);
    return sessionId;
  }

  async storeRefreshToken(
    refreshTokenHash: string,
    userId: string,
    sessionId: string,
    ttlSeconds: number,
    ip: string,
    userAgent?: string,
  ): Promise<void> {
    const now = Date.now();
    const refreshKey = `${this.REFRESH_PREFIX}${refreshTokenHash}`;
    const sessionRefreshKey = `${this.SESSION_REFRESH_PREFIX}${sessionId}`;

    const refreshData: RefreshTokenData = {
      userId,
      sessionId,
      ip,
      userAgent,
      createdAt: now,
    };

    const multi = this.redis.multi();
    multi.setex(refreshKey, ttlSeconds, JSON.stringify(refreshData));
    multi.setex(sessionRefreshKey, ttlSeconds, refreshTokenHash);
    await multi.exec();

    this.logger.debug(
      `Stored refresh token hash for user=${userId} session=${sessionId} ttl=${ttlSeconds}s`,
    );
  }

  async getRefreshTokenData(refreshTokenHash: string): Promise<RefreshTokenData | null> {
    const raw = await this.redis.get(`${this.REFRESH_PREFIX}${refreshTokenHash}`);
    if (!raw) return null;

    try {
      return JSON.parse(raw) as RefreshTokenData;
    } catch {
      this.logger.warn(`Invalid refresh token JSON for hash=${refreshTokenHash}`);
      return null;
    }
  }

  async getSessionRefreshTokenHash(sessionId: string): Promise<string | null> {
    return this.redis.get(`${this.SESSION_REFRESH_PREFIX}${sessionId}`);
  }

  async rotateRefreshToken(
    oldRefreshTokenHash: string,
    newRefreshTokenHash: string,
    ttlSeconds: number,
    ip: string,
    userAgent?: string,
  ): Promise<RefreshTokenData | null> {
    const existing = await this.getRefreshTokenData(oldRefreshTokenHash);
    if (!existing) {
      this.logger.warn(`Rotate refresh failed, old hash not found hash=${oldRefreshTokenHash}`);
      return null;
    }

    const refreshKeyOld = `${this.REFRESH_PREFIX}${oldRefreshTokenHash}`;
    const refreshKeyNew = `${this.REFRESH_PREFIX}${newRefreshTokenHash}`;
    const sessionRefreshKey = `${this.SESSION_REFRESH_PREFIX}${existing.sessionId}`;

    const nextData: RefreshTokenData = {
      userId: existing.userId,
      sessionId: existing.sessionId,
      ip,
      userAgent,
      createdAt: Date.now(),
    };

    const multi = this.redis.multi();
    multi.del(refreshKeyOld);
    multi.setex(refreshKeyNew, ttlSeconds, JSON.stringify(nextData));
    multi.setex(sessionRefreshKey, ttlSeconds, newRefreshTokenHash);
    await multi.exec();

    this.logger.debug(
      `Rotated refresh token hash for user=${existing.userId} session=${existing.sessionId}`,
    );

    return nextData;
  }

  async revokeRefreshToken(refreshTokenHash: string): Promise<void> {
    const refreshData = await this.getRefreshTokenData(refreshTokenHash);
    if (refreshData?.sessionId) {
      await this.redis.del(`${this.SESSION_REFRESH_PREFIX}${refreshData.sessionId}`);
    }

    await this.redis.del(`${this.REFRESH_PREFIX}${refreshTokenHash}`);
    this.logger.debug(`Revoked refresh token hash=${refreshTokenHash}`);
  }

  async validateSession(sessionId: string): Promise<SessionData | null> {
    const sessionKey = `${this.SESSION_PREFIX}${sessionId}`;
    const sessionDataStr = await this.redis.get(sessionKey);

    if (!sessionDataStr) {
      return null;
    }

    try {
      const sessionData = JSON.parse(sessionDataStr) as SessionData;
      sessionData.lastUsed = Date.now();

      const ttl = await this.redis.ttl(sessionKey);
      if (ttl > 0) {
        await this.redis.setex(sessionKey, ttl, JSON.stringify(sessionData));
      }

      return sessionData;
    } catch {
      this.logger.warn(`Invalid session JSON for session=${sessionId}`);
      return null;
    }
  }

  async revokeSession(sessionId: string): Promise<void> {
    const sessionData = await this.getSessionData(sessionId);
    if (sessionData) {
      await this.removeFromUserSessions(sessionData.userId, sessionId);
    }

    const refreshHash = await this.getSessionRefreshTokenHash(sessionId);
    const multi = this.redis.multi();
    multi.del(`${this.SESSION_PREFIX}${sessionId}`);
    multi.del(`${this.SESSION_REFRESH_PREFIX}${sessionId}`);
    if (refreshHash) {
      multi.del(`${this.REFRESH_PREFIX}${refreshHash}`);
    }
    await multi.exec();

    this.logger.debug(`Revoked session ${sessionId}`);
  }

  async getUserSessions(userId: string): Promise<string[]> {
    const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
    const sessionIds = await this.redis.smembers(userSessionsKey);

    const activeSessions: string[] = [];
    for (const sessionId of sessionIds) {
      const exists = await this.redis.exists(`${this.SESSION_PREFIX}${sessionId}`);
      if (exists) {
        activeSessions.push(sessionId);
      } else {
        await this.redis.srem(userSessionsKey, sessionId);
        this.logger.debug(`Removed stale session reference user=${userId} session=${sessionId}`);
      }
    }

    return activeSessions;
  }

  async revokeAllSessions(userId: string): Promise<number> {
    const sessionIds = await this.getUserSessions(userId);

    for (const sessionId of sessionIds) {
      await this.revokeSession(sessionId);
    }

    await this.redis.del(`${this.USER_SESSIONS_PREFIX}${userId}`);
    this.logger.log(`Revoked all ${sessionIds.length} sessions for user ${userId}`);
    return sessionIds.length;
  }

  async revokeAllOtherSessions(userId: string, currentSessionId: string): Promise<number> {
    const sessionIds = await this.getUserSessions(userId);
    let revoked = 0;

    for (const sessionId of sessionIds) {
      if (sessionId !== currentSessionId) {
        await this.revokeSession(sessionId);
        revoked++;
      }
    }

    return revoked;
  }

  async extendSession(sessionId: string, ttlSeconds: number): Promise<boolean> {
    const sessionKey = `${this.SESSION_PREFIX}${sessionId}`;
    const sessionData = await this.getSessionData(sessionId);

    if (!sessionData) {
      return false;
    }

    const refreshHash = await this.getSessionRefreshTokenHash(sessionId);
    const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${sessionData.userId}`;

    const multi = this.redis.multi();
    multi.expire(sessionKey, ttlSeconds);
    multi.expire(`${this.SESSION_REFRESH_PREFIX}${sessionId}`, ttlSeconds);
    if (refreshHash) {
      multi.expire(`${this.REFRESH_PREFIX}${refreshHash}`, ttlSeconds);
    }
    multi.expire(userSessionsKey, ttlSeconds + 3600);
    await multi.exec();

    return true;
  }

  async blacklistJti(jti: string, ttlSeconds: number): Promise<void> {
    if (!jti || ttlSeconds <= 0) {
      return;
    }
    await this.redis.setex(`${this.BLACKLIST_PREFIX}${jti}`, ttlSeconds, "1");
    this.logger.debug(`Blacklisted jti=${jti} ttl=${ttlSeconds}s`);
  }

  async isJtiBlacklisted(jti: string): Promise<boolean> {
    if (!jti) return false;
    const exists = await this.redis.exists(`${this.BLACKLIST_PREFIX}${jti}`);
    return exists === 1;
  }

  async getLoginAttempts(identifier: string): Promise<number> {
    const count = await this.redis.get(`${this.LOGIN_ATTEMPTS_PREFIX}${identifier}`);
    return count ? Number(count) : 0;
  }

  async incrementLoginAttempts(identifier: string, ttlSeconds = 15 * 60): Promise<number> {
    const key = `${this.LOGIN_ATTEMPTS_PREFIX}${identifier}`;
    const attempts = await this.redis.incr(key);
    if (attempts === 1) {
      await this.redis.expire(key, ttlSeconds);
    }
    this.logger.warn(`Login attempts incremented identifier=${identifier} attempts=${attempts}`);
    return attempts;
  }

  async clearLoginAttempts(identifier: string): Promise<void> {
    await this.redis.del(`${this.LOGIN_ATTEMPTS_PREFIX}${identifier}`);
    this.logger.debug(`Cleared login attempts identifier=${identifier}`);
  }

  async registerIpAttempt(ip: string, windowSeconds: number): Promise<number> {
    const key = `${this.RATE_LIMIT_PREFIX}${ip}`;
    const now = Date.now();
    const windowStart = now - windowSeconds * 1000;

    const multi = this.redis.multi();
    multi.zremrangebyscore(key, 0, windowStart);
    multi.zadd(key, now, `${now}:${randomBytes(8).toString("hex")}`);
    multi.zcard(key);
    multi.expire(key, windowSeconds);
    const result = await multi.exec();

    const zcard = result?.[2]?.[1];
    const attempts = typeof zcard === "number" ? zcard : Number(zcard || 0);
    return attempts;
  }

  async getSessionCount(userId: string): Promise<number> {
    const sessions = await this.getUserSessions(userId);
    return sessions.length;
  }

  private generateSessionId(): string {
    return randomBytes(32).toString("hex");
  }

  private async getSessionData(sessionId: string): Promise<SessionData | null> {
    const sessionDataStr = await this.redis.get(`${this.SESSION_PREFIX}${sessionId}`);
    if (!sessionDataStr) return null;

    try {
      return JSON.parse(sessionDataStr);
    } catch {
      this.logger.warn(`Invalid session JSON while loading session=${sessionId}`);
      return null;
    }
  }

  private async addToUserSessions(userId: string, sessionId: string, ttl: number): Promise<void> {
    const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
    await this.redis.sadd(userSessionsKey, sessionId);
    await this.redis.expire(userSessionsKey, ttl + 3600);
  }

  private async removeFromUserSessions(userId: string, sessionId: string): Promise<void> {
    const userSessionsKey = `${this.USER_SESSIONS_PREFIX}${userId}`;
    await this.redis.srem(userSessionsKey, sessionId);
  }
}