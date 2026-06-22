import { Body, Controller, Get, Post, Req, Res, UseGuards } from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiBody,
  ApiCookieAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";
import type { Request, Response } from "express";
import { GetCurrentUser, GetCurrentUserId, JwtAuthGuard, Public } from "@repo/auth";
import type { JwtPayload } from "@repo/auth/types";

import { AuthService } from "./auth.service";

@ApiTags("Auth")
@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post("login/web")
  @ApiOperation({ summary: "Sign in via web (sets httpOnly cookies)" })
  @ApiBody({
    schema: {
      properties: { email: { type: "string" }, password: { type: "string" } },
    },
  })
  @ApiResponse({ status: 200, description: "Logged in, cookies set" })
  @ApiResponse({ status: 401, description: "Invalid credentials" })
  async loginWeb(
    @Body() body: { email: string; password: string },
    @Res({ passthrough: true }) response: Response,
  ) {
    const tokens = await this.authService.signIn(body.email, body.password);
    this.authService.setAuthCookies(tokens, response);
    return { message: "ok" };
  }

  @Public()
  @Post("login/mobile")
  @ApiOperation({ summary: "Sign in via mobile (returns tokens in body)" })
  @ApiBody({
    schema: {
      properties: { email: { type: "string" }, password: { type: "string" } },
    },
  })
  @ApiResponse({ status: 200, description: "Returns access and refresh tokens" })
  @ApiResponse({ status: 401, description: "Invalid credentials" })
  async loginMobile(@Body() body: { email: string; password: string }) {
    return this.authService.signIn(body.email, body.password);
  }

  @Public()
  @Post("refresh")
  @ApiCookieAuth("refresh_token")
  @ApiOperation({ summary: "Refresh tokens via cookie (web)" })
  @ApiResponse({ status: 200, description: "New tokens set in cookies" })
  @ApiResponse({ status: 401, description: "Invalid refresh token" })
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    const token = this.authService.extractRefreshToken(req);
    const tokens = await this.authService.refreshToken(token);
    this.authService.setAuthCookies(tokens, response);
    return { message: "ok" };
  }

  @Public()
  @Post("refresh/mobile")
  @ApiOperation({ summary: "Refresh tokens via x-refresh-token header (mobile)" })
  @ApiResponse({ status: 200, description: "Returns new access and refresh tokens" })
  @ApiResponse({ status: 401, description: "Invalid refresh token" })
  async refreshMobile(@Req() req: Request) {
    const token = this.authService.extractRefreshToken(req);
    return this.authService.refreshToken(token);
  }

  @Get("me")
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiCookieAuth("access_token")
  @ApiOperation({ summary: "Get current user profile" })
  @ApiResponse({ status: 200, description: "Current user JWT payload" })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  getProfile(@GetCurrentUser() user: JwtPayload) {
    return user;
  }

  @Get("me/id")
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiCookieAuth("access_token")
  @ApiOperation({ summary: "Get current user ID" })
  @ApiResponse({ status: 200, description: "Current user ID" })
  getUserId(@GetCurrentUserId() userId: string) {
    return { userId };
  }

  @Public()
  @Get("health")
  @ApiOperation({ summary: "Health check" })
  @ApiResponse({ status: 200, description: "Server is healthy" })
  health() {
    return { status: "ok" };
  }
}