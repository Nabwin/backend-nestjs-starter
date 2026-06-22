import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import type { Request, Response } from "express";

import { AppleOAuthClientService } from "src/oauth/apple/apple-oauth-client.service";
import { OAuthProvidersService } from "src/oauth/oauth-providers.service";
import { OAuthService } from "src/oauth/oauth.service";
import { OAUTH_METHOD } from "src/oauth/types/enums";
import { OAuthProvider } from "src/oauth/types/oauth-profile.type";

function encodeState(deviceType: string): string {
  return Buffer.from(JSON.stringify({ deviceType })).toString("base64");
}

@Injectable()
export class AppleOAuthGuard implements CanActivate {
  constructor(
    private readonly appleClient: AppleOAuthClientService,
    private readonly oauthService: OAuthService,
    private readonly providersService: OAuthProvidersService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (!this.providersService.isEnabled(OAUTH_METHOD.APPLE)) {
      throw new BadRequestException("Apple OAuth is not enabled");
    }

    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    if (request.method === "GET") {
      const deviceType =
        (request.query?.deviceType as string) ||
        (request.query?.device_type as string) ||
        "web";
      const state = encodeState(deviceType);
      const authUrl = this.appleClient.buildAuthorizationUrl(state);
      response.redirect(authUrl);
      return false;
    }

    const body = request.body as Record<string, unknown> | undefined;

    if (!body || typeof body.code !== "string") {
      if (body?.error === "user_cancelled_authorize") {
        throw new UnauthorizedException("User cancelled Apple authorization");
      }
      throw new UnauthorizedException(
        "Apple OAuth callback missing authorization code",
      );
    }

    const appleProfile = await this.appleClient.authenticateCode(
      body.code as string,
      body.user,
    );

    const user = await this.oauthService.upsertOAuthUser({
      provider: OAuthProvider.APPLE,
      providerId: appleProfile.id,
      email: appleProfile.email ?? "",
      firstName: appleProfile.name?.firstName,
      lastName: appleProfile.name?.lastName,
      isEmailVerified: appleProfile.emailVerified,
    });

    (request as Request & { user: unknown }).user = user;
    return true;
  }
}

@Injectable()
export class AppleMobileOAuthGuard implements CanActivate {
  constructor(
    private readonly appleClient: AppleOAuthClientService,
    private readonly oauthService: OAuthService,
    private readonly providersService: OAuthProvidersService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (!this.providersService.isEnabled(OAUTH_METHOD.APPLE)) {
      throw new BadRequestException("Apple OAuth is not enabled");
    }

    const request = context.switchToHttp().getRequest<Request>();
    const body = request.body as Record<string, unknown> | undefined;

    if (!body || typeof body.identityToken !== "string") {
      throw new UnauthorizedException(
        "Missing identityToken from Apple Sign-In",
      );
    }

    if (!body.user) {
      throw new UnauthorizedException(
        "Missing user identifier from Apple Sign-In",
      );
    }

    const appleProfile = await this.appleClient.authenticateMobile({
      identityToken: body.identityToken as string,
      user: body.user as string,
      fullName: body.fullName as
        | { givenName?: string; familyName?: string }
        | undefined,
      email: body.email as string | undefined,
    });

    const user = await this.oauthService.upsertOAuthUser({
      provider: OAuthProvider.APPLE,
      providerId: appleProfile.id,
      email: appleProfile.email ?? "",
      firstName: appleProfile.name?.firstName,
      lastName: appleProfile.name?.lastName,
      isEmailVerified: appleProfile.emailVerified,
    });

    (request as Request & { user: unknown }).user = user;
    return true;
  }
}