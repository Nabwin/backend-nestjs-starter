import {
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import type { Request, Response } from "express";

import { AuthService } from "src/auth/auth.service";
import {
  AppleMobileOAuthGuard,
  AppleOAuthGuard,
} from "src/oauth/guards/apple-oauth.guards";
import {
  FacebookOAuthGuard,
  GoogleOAuthGuard,
  LinkedInOAuthGuard,
} from "src/oauth/guards/oauth.guards";
import { OAUTH_METHOD } from "src/oauth/types/enums";

interface OAuthCallbackUser {
  id: string;
  email: string;
  role: string;
}

interface OAuthState {
  deviceType: string;
}

function parseState(raw?: string): OAuthState {
  if (!raw) return { deviceType: "web" };
  try {
    return JSON.parse(Buffer.from(raw, "base64").toString("utf-8")) as OAuthState;
  } catch {
    return { deviceType: "web" };
  }
}

function isMobile(deviceType?: string): boolean {
  return deviceType?.toLowerCase() === "mobile";
}

@Controller("oauth")
export class OAuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
  ) {}

  private async handleCallback(
    user: OAuthCallbackUser,
    provider: string,
    state: string | undefined,
    req: Request,
    res: Response,
  ) {
    const { deviceType } = parseState(state);
    const mobile = isMobile(deviceType);
    const frontendUrl = this.config.get("FRONTEND_URL");

    const binding = {
      ip: this.authService.getClientIp(req),
      userAgent: req.get("user-agent") || undefined,
    };

    try {
      if (mobile) {
        const tokens = await this.authService.userLoginMobile(user, binding);
        const params = new URLSearchParams({
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          provider,
          deviceType,
        });
        return res.redirect(`${frontendUrl}/auth/oauth-success?${params.toString()}`);
      }

      await this.authService.userLoginWeb(user, res, binding);
      return res.redirect(frontendUrl!);
    } catch (error) {
      const message = error instanceof Error ? error.message : "OAuth failed";
      const redirectBase = mobile
        ? `${frontendUrl}/auth/oauth-error`
        : `${frontendUrl}/auth/oauth-error`;
      const params = new URLSearchParams({
        error: message,
        deviceType,
        provider,
      });
      return res.redirect(`${redirectBase}?${params.toString()}`);
    }
  }

  @Get("google")
  @UseGuards(GoogleOAuthGuard)
  googleLogin() {}

  @Get("google/callback")
  @UseGuards(GoogleOAuthGuard)
  async googleCallback(
    @Req() req: Request & { user: OAuthCallbackUser },
    @Res() res: Response,
    @Query("state") state?: string,
  ) {
    return this.handleCallback(req.user, OAUTH_METHOD.GOOGLE, state, req, res);
  }

  @Get("facebook")
  @UseGuards(FacebookOAuthGuard)
  facebookLogin() {}

  @Get("facebook/callback")
  @UseGuards(FacebookOAuthGuard)
  async facebookCallback(
    @Req() req: Request & { user: OAuthCallbackUser },
    @Res() res: Response,
    @Query("state") state?: string,
  ) {
    return this.handleCallback(req.user, OAUTH_METHOD.FACEBOOK, state, req, res);
  }

  @Get("apple")
  @UseGuards(AppleOAuthGuard)
  appleLogin() {}

  @Post("apple/callback")
  @UseGuards(AppleOAuthGuard)
  async appleCallback(
    @Req() req: Request & { user: OAuthCallbackUser },
    @Res() res: Response,
  ) {
    const body = req.body as Record<string, unknown> | undefined;
    const state = typeof body?.state === "string" ? (body.state as string) : undefined;
    return this.handleCallback(req.user, OAUTH_METHOD.APPLE, state, req, res);
  }

  @Post("apple/mobile/callback")
  @UseGuards(AppleMobileOAuthGuard)
  async appleMobileCallback(
    @Req() req: Request & { user: OAuthCallbackUser },
  ) {
    const binding = {
      ip: this.authService.getClientIp(req),
      userAgent: req.get("user-agent") || undefined,
    };
    return this.authService.userLoginMobile(req.user, binding);
  }

  @Get("linkedin")
  @UseGuards(LinkedInOAuthGuard)
  linkedinLogin() {}

  @Get("linkedin/callback")
  @UseGuards(LinkedInOAuthGuard)
  async linkedinCallback(
    @Req() req: Request & { user: OAuthCallbackUser },
    @Res() res: Response,
    @Query("state") state?: string,
  ) {
    return this.handleCallback(req.user, OAUTH_METHOD.LINKEDIN, state, req, res);
  }
}