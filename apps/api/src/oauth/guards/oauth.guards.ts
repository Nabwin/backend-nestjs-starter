import { BadRequestException, ExecutionContext, Injectable } from "@nestjs/common";
import { ModuleRef } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";
import type { Request } from "express";

import { OAuthProvidersService } from "src/oauth/oauth-providers.service";
import { OAUTH_METHOD, type OAuthMethod } from "src/oauth/types/enums";

function encodeState(deviceType: string): string {
  return Buffer.from(JSON.stringify({ deviceType })).toString("base64");
}

function oauthGuard(provider: OAuthMethod) {
  @Injectable()
  class Guard extends AuthGuard(provider) {
    providersService: OAuthProvidersService | null = null;

    constructor(readonly moduleRef: ModuleRef) {
      super();
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
      if (!this.providersService) {
        this.providersService = this.moduleRef.get(OAuthProvidersService, {
          strict: false,
        });
      }
      if (!this.providersService!.isEnabled(provider)) {
        throw new BadRequestException(`${provider} OAuth is not enabled`);
      }
      return (await super.canActivate(context)) as boolean;
    }

    getAuthenticateOptions(context: ExecutionContext) {
      const req = context.switchToHttp().getRequest<Request>();
      const deviceType =
        (req.query?.deviceType as string) ||
        (req.query?.device_type as string) ||
        "web";
      return { state: encodeState(deviceType) };
    }
  }

  return Guard;
}

export const GoogleOAuthGuard = oauthGuard(OAUTH_METHOD.GOOGLE);
export const FacebookOAuthGuard = oauthGuard(OAUTH_METHOD.FACEBOOK);
export const LinkedInOAuthGuard = oauthGuard(OAUTH_METHOD.LINKEDIN);