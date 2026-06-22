import { Module, forwardRef } from "@nestjs/common";

import { AuthModule } from "src/auth/auth.module";
import { AppleOAuthClientService } from "src/oauth/apple/apple-oauth-client.service";
import {
  AppleMobileOAuthGuard,
  AppleOAuthGuard,
} from "src/oauth/guards/apple-oauth.guards";
import {
  FacebookOAuthGuard,
  GoogleOAuthGuard,
  LinkedInOAuthGuard,
} from "src/oauth/guards/oauth.guards";
import { OAuthController } from "src/oauth/oauth.controller";
import { OAuthProvidersService } from "src/oauth/oauth-providers.service";
import { OAuthService } from "src/oauth/oauth.service";
import { FacebookOAuthStrategy } from "src/oauth/strategies/facebook-oauth.strategy";
import { GoogleOAuthStrategy } from "src/oauth/strategies/google-oauth.strategy";
import { LinkedInOAuthStrategy } from "src/oauth/strategies/linkedin-oauth.strategy";

@Module({
  imports: [forwardRef(() => AuthModule)],
  controllers: [OAuthController],
  providers: [
    OAuthService,
    OAuthProvidersService,
    GoogleOAuthStrategy,
    FacebookOAuthStrategy,
    LinkedInOAuthStrategy,
    AppleOAuthClientService,
    GoogleOAuthGuard,
    FacebookOAuthGuard,
    LinkedInOAuthGuard,
    AppleOAuthGuard,
    AppleMobileOAuthGuard,
  ],
  exports: [OAuthService, OAuthProvidersService],
})
export class OAuthModule {}