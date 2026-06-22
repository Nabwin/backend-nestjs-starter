import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { Profile, Strategy, VerifyCallback } from "passport-google-oauth20";

import type { EnvValidationType } from "src/env.validation";
import { OAuthService } from "src/oauth/oauth.service";
import { OAuthProvider } from "src/oauth/types/oauth-profile.type";

@Injectable()
export class GoogleOAuthStrategy extends PassportStrategy(Strategy, "google") {
  constructor(
    config: ConfigService<EnvValidationType, true>,
    private readonly oauthService: OAuthService,
  ) {
    const clientId = config.get("GOOGLE_CLIENT_ID");
    const clientSecret = config.get("GOOGLE_CLIENT_SECRET");
    const backendUrl = config.get("BACKEND_URL");

    super({
      clientID: clientId || "GOOGLE_CLIENT_ID",
      clientSecret: clientSecret || "GOOGLE_CLIENT_SECRET",
      callbackURL: `${backendUrl}/api/v1/oauth/google/callback`,
      scope: ["profile", "email"],
    });
  }

  async validate(
    _accessToken: string,
    _refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ) {
    const user = await this.oauthService.upsertOAuthUser({
      provider: OAuthProvider.GOOGLE,
      providerId: profile.id,
      email: profile.emails?.[0]?.value || "",
      firstName: profile.name?.givenName,
      lastName: profile.name?.familyName,
      profilePicture: profile.photos?.[0]?.value,
      isEmailVerified: profile.emails?.[0]?.verified,
    });

    done(null, user);
  }
}