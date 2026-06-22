import { BadRequestException, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { decodeJwt } from "jose";
import { Strategy } from "passport-linkedin-oauth2";

import type { EnvValidationType } from "src/env.validation";
import { OAuthService } from "src/oauth/oauth.service";
import { OAuthProvider } from "src/oauth/types/oauth-profile.type";

interface LinkedInTokenParams {
  id_token?: string;
}

interface LinkedInIdTokenClaims {
  sub?: string;
  email?: string;
  email_verified?: boolean;
  given_name?: string;
  family_name?: string;
  name?: string;
  picture?: string;
}

@Injectable()
export class LinkedInOAuthStrategy extends PassportStrategy(Strategy, "linkedin") {
  constructor(
    config: ConfigService<EnvValidationType, true>,
    private readonly oauthService: OAuthService,
  ) {
    super({
      clientID: config.get("LINKEDIN_CLIENT_ID") || "LINKEDIN_CLIENT_ID",
      clientSecret: config.get("LINKEDIN_CLIENT_SECRET") || "LINKEDIN_CLIENT_SECRET",
      callbackURL: `${config.get("BACKEND_URL")}/api/v1/oauth/linkedin/callback`,
      scope: ["openid", "profile", "email"],
      skipUserProfile: true,
    } as any);
  }

  async validate(
    _accessToken: string,
    _refreshToken: string,
    params: LinkedInTokenParams,
  ) {
    let claims: LinkedInIdTokenClaims = {};

    if (params.id_token) {
      try {
        claims = decodeJwt(params.id_token) as LinkedInIdTokenClaims;
      } catch {
        throw new BadRequestException("Invalid LinkedIn id_token");
      }
    }

    const providerId = claims.sub;
    if (!providerId) {
      throw new BadRequestException("LinkedIn did not return a valid user identifier");
    }

    const displayName = claims.name;
    const firstName = claims.given_name || displayName?.split(" ")[0] || undefined;
    const lastName =
      claims.family_name || displayName?.split(" ").slice(1).join(" ") || undefined;

    return this.oauthService.upsertOAuthUser({
      provider: OAuthProvider.LINKEDIN,
      providerId,
      email: claims.email || "",
      firstName,
      lastName,
      profilePicture: claims.picture,
      isEmailVerified: true,
    });
  }
}