import { Body, Controller, Get, Post, UseGuards } from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiBody,
  ApiCookieAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";
import { GetCurrentUser, GetCurrentUserId, JwtAuthGuard, Public } from "@repo/auth";
import type { JwtPayload } from "@repo/auth/types";

import { AuthService } from "./auth.service";

@ApiTags("Auth")
@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post("signin")
  @ApiOperation({ summary: "Sign in with email and password" })
  @ApiBody({
    schema: {
      properties: { email: { type: "string" }, password: { type: "string" } },
    },
  })
  @ApiResponse({
    status: 200,
    description: "Returns access and refresh tokens",
  })
  @ApiResponse({ status: 401, description: "Invalid credentials" })
  async signIn(@Body() body: { email: string; password: string }) {
    return this.authService.signIn(body.email, body.password);
  }

  @Public()
  @Post("refresh")
  @ApiOperation({ summary: "Refresh access token" })
  @ApiBody({ schema: { properties: { refreshToken: { type: "string" } } } })
  @ApiResponse({
    status: 200,
    description: "Returns new access and refresh tokens",
  })
  @ApiResponse({ status: 401, description: "Invalid refresh token" })
  async refresh(@Body() body: { refreshToken: string }) {
    return this.authService.refreshToken(body.refreshToken);
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
