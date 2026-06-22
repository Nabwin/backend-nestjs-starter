import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { Profile, Strategy } from "passport-facebook";

import type { EnvValidationType } from "src/env.validation";
import { OAuthService } from "src/oauth/oauth.service";
import { OAuthProvider } from "src/oauth/types/oauth-profile.type";

@Injectable()
export class FacebookOAuthStrategy extends PassportStrategy(Strategy, "facebook") {
  constructor(
    config: ConfigService<EnvValidationType, true>,
    private readonly oauthService: OAuthService,
  ) {
    const clientId = config.get("FACEBOOK_CLIENT_ID") || "FACEBOOK_CLIENT_ID";
    const clientSecret = config.get("FACEBOOK_CLIENT_SECRET") || "FACEBOOK_CLIENT_SECRET";
    const backendUrl = config.get("BACKEND_URL");

    super({
      clientID: clientId,
      clientSecret,
      callbackURL: `${backendUrl}/api/v1/oauth/facebook/callback`,
      scope: ["email", "public_profile"],
      profileFields: ["id", "emails", "name", "photos"],
    });
  }

  async validate(
    _accessToken: string,
    _refreshToken: string,
    profile: Profile,
    done: (error: unknown, user?: unknown, info?: unknown) => void,
  ) {
    const user = await this.oauthService.upsertOAuthUser({
      provider: OAuthProvider.FACEBOOK,
      providerId: profile.id,
      email: profile.emails?.[0]?.value || "",
      firstName: profile.name?.givenName,
      lastName: profile.name?.familyName,
      profilePicture: profile.photos?.[0]?.value,
      isEmailVerified: true,
    });

    done(null, user);
  }
}