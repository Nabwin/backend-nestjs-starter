import { Injectable, Logger, OnModuleInit } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { readFileSync } from "fs";
import { createRemoteJWKSet, importPKCS8, jwtVerify, SignJWT } from "jose";

import type { EnvValidationType } from "src/env.validation";
import type { AppleProfile } from "src/oauth/apple/apple-profile.interface";

const APPLE_JWKS_URL = new URL("https://appleid.apple.com/auth/keys");
const APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token";
const APPLE_AUTH_URL = "https://appleid.apple.com/auth/authorize";
const APPLE_ISSUER = "https://appleid.apple.com";
const CLIENT_SECRET_TTL = 300;

interface AppleTokenResponse {
  access_token: string;
  id_token: string;
}

interface AppleIdTokenClaims {
  sub: string;
  email?: string;
  email_verified?: string | boolean;
}

export interface AppleMobilePayload {
  identityToken: string;
  user: string;
  fullName?: {
    givenName?: string;
    familyName?: string;
  };
  email?: string;
}

interface CachedSecret {
  token: string;
  expiresAt: number;
}

@Injectable()
export class AppleOAuthClientService implements OnModuleInit {
  private readonly logger = new Logger(AppleOAuthClientService.name);

  private readonly webClientId: string;
  private readonly mobileClientId: string;
  private readonly teamId: string;
  private readonly keyId: string;
  private readonly callbackUrl: string;

  private readonly jwks: ReturnType<typeof createRemoteJWKSet> | null;
  private privateKey: CryptoKey | null = null;
  private cachedSecret: CachedSecret | null = null;

  private readonly isWebConfigured: boolean;
  private readonly isMobileConfigured: boolean;

  constructor(
    private readonly config: ConfigService<EnvValidationType, true>,
  ) {
    const bundleId = this.config.get("APPLE_BUNDLE_ID");
    const clientId = this.config.get("APPLE_CLIENT_ID");
    const teamId = this.config.get("APPLE_TEAM_ID");
    const keyId = this.config.get("APPLE_KEY_ID");
    const keyPath = this.config.get("APPLE_PRIVATE_KEY_PATH");

    this.isMobileConfigured = !!(bundleId && bundleId !== "" && keyPath);
    this.mobileClientId = bundleId || "";

    this.isWebConfigured = !!(clientId && clientId !== "" && teamId && keyId && keyPath);
    this.webClientId = clientId || "";
    this.teamId = teamId || "";
    this.keyId = keyId || "";

    if (this.isMobileConfigured) {
      this.jwks = createRemoteJWKSet(APPLE_JWKS_URL);
    } else {
      this.jwks = null;
    }

    if (this.isWebConfigured) {
      try {
        const rawKey = readFileSync(keyPath!, "utf-8");
        const backendUrl = this.config.get("BACKEND_URL");
        this.callbackUrl = `${backendUrl}/api/v1/oauth/apple/callback`;

        importPKCS8(rawKey, "ES256").then((key) => {
          this.privateKey = key;
        });
      } catch (err) {
        this.logger.error(`Failed to load Apple private key: ${(err as Error).message}`);
        this.isWebConfigured = false;
        this.callbackUrl = "";
      }
    } else {
      this.callbackUrl = "";
    }
  }

  onModuleInit() {
    if (!this.isWebConfigured && !this.isMobileConfigured) {
      this.logger.warn("Apple OAuth is not configured — both web and mobile are disabled");
    }
  }

  buildAuthorizationUrl(state: string): string {
    if (!this.isWebConfigured) {
      throw new Error("Apple Web OAuth is not configured");
    }

    const params = new URLSearchParams({
      client_id: this.webClientId,
      redirect_uri: this.callbackUrl,
      response_type: "code",
      response_mode: "form_post",
      scope: "email name",
      state,
    });

    return `${APPLE_AUTH_URL}?${params.toString()}`;
  }

  async authenticateCode(code: string, userBody?: unknown): Promise<AppleProfile> {
    if (!this.isWebConfigured) {
      throw new Error("Apple Web OAuth is not configured");
    }

    const tokens = await this.exchangeCode(code);
    const claims = await this.verifyIdToken(tokens.id_token, this.webClientId);
    return this.buildProfile(claims, userBody);
  }

  async authenticateMobile(payload: AppleMobilePayload): Promise<AppleProfile> {
    if (!this.isMobileConfigured) {
      throw new Error("Apple Mobile OAuth is not configured");
    }

    const claims = await this.verifyIdToken(payload.identityToken, this.mobileClientId);
    return this.buildProfile(claims, payload);
  }

  private async getClientSecret(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    if (this.cachedSecret && this.cachedSecret.expiresAt > now + 10) {
      return this.cachedSecret.token;
    }

    if (!this.privateKey) {
      throw new Error("Apple private key not loaded");
    }

    const token = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: this.keyId })
      .setIssuer(this.teamId)
      .setAudience(APPLE_ISSUER)
      .setSubject(this.webClientId)
      .setIssuedAt(now)
      .setExpirationTime(now + CLIENT_SECRET_TTL)
      .sign(this.privateKey);

    this.cachedSecret = { token, expiresAt: now + CLIENT_SECRET_TTL };
    return token;
  }

  private async exchangeCode(code: string): Promise<AppleTokenResponse> {
    const clientSecret = await this.getClientSecret();

    const body = new URLSearchParams({
      client_id: this.webClientId,
      client_secret: clientSecret,
      code,
      grant_type: "authorization_code",
      redirect_uri: this.callbackUrl,
    });

    const response = await fetch(APPLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Apple token exchange failed: ${response.status} — ${text}`);
    }

    return response.json() as Promise<AppleTokenResponse>;
  }

  private async verifyIdToken(idToken: string, audience: string): Promise<AppleIdTokenClaims> {
    if (!this.jwks) {
      throw new Error("Apple JWKS not initialized");
    }

    const { payload } = await jwtVerify(idToken, this.jwks!, {
      issuer: APPLE_ISSUER,
      audience,
      algorithms: ["RS256"],
    });

    return payload as unknown as AppleIdTokenClaims;
  }

  private buildProfile(claims: AppleIdTokenClaims, userBody?: unknown): AppleProfile {
    const profile: AppleProfile = { id: claims.sub };

    if (claims.email) profile.email = claims.email;
    if (claims.email_verified !== undefined) {
      profile.emailVerified =
        claims.email_verified === "true" || claims.email_verified === true;
    }

    if (userBody && typeof userBody === "object" && userBody !== null) {
      this.extractName(profile, userBody as Record<string, unknown>);
    }

    return profile;
  }

  private extractName(profile: AppleProfile, body: Record<string, unknown>): void {
    try {
      const source = (body.fullName ?? body.user ?? body) as Record<string, unknown> | undefined;
      if (!source || typeof source !== "object") return;

      const name =
        (source.name as Record<string, unknown> | undefined) ?? source;

      if (name && typeof name === "object") {
        const firstName =
          (name.firstName as string) || (name.givenName as string) || undefined;
        const lastName =
          (name.lastName as string) || (name.familyName as string) || undefined;

        if (firstName || lastName) {
          profile.name = { firstName, lastName };
        }
      }
    } catch {
      // best-effort name extraction
    }
  }
}