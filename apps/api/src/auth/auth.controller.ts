import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiBody,
  ApiCookieAuth,
  ApiHeader,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";
import type { Request, Response } from "express";
import { GetCurrentUser, GetCurrentUserId, JwtAuthGuard, Public } from "@repo/auth";
import type { JwtPayload } from "@repo/auth/types";

import { AuthService } from "./auth.service";

interface JwtPayloadWithSession extends JwtPayload {
  refreshToken?: string;
  sessionId?: string;
  jti?: string;
  exp?: number;
}

@ApiTags("Auth")
@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post("register")
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: "Register a new account" })
  @ApiBody({
    schema: {
      properties: {
        email: { type: "string" },
        password: { type: "string" },
        fullName: { type: "string" },
      },
      required: ["email", "password"],
    },
  })
  @ApiResponse({ status: 201, description: "Account created" })
  @ApiResponse({ status: 409, description: "Email already taken" })
  async register(
    @Body() body: { email: string; password: string; fullName?: string },
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const ip = this.authService.getClientIp(req);
    const userAgent = req.get("user-agent") || undefined;
    const tokens = await this.authService.signUp(body.email, body.password, body.fullName, ip, userAgent);
    this.authService.setAuthCookies(res, tokens);
    return { message: "Registration successful" };
  }

  @Public()
  @Post("login/web")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Sign in via web (sets httpOnly cookies)" })
  @ApiBody({
    schema: {
      properties: { email: { type: "string" }, password: { type: "string" } },
    },
  })
  @ApiResponse({ status: 200, description: "Logged in, cookies set" })
  @ApiResponse({ status: 401, description: "Invalid credentials" })
  @ApiResponse({ status: 498, description: "Access token expired" })
  async loginWeb(
    @Body() body: { email: string; password: string },
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const ip = this.authService.getClientIp(req);
    const userAgent = req.get("user-agent") || undefined;
    const result = await this.authService.signIn(body.email, body.password, ip, userAgent, "web");
    this.authService.setAuthCookies(res, result);
    return { role: result.role, message: "Login successful" };
  }

  @Public()
  @Post("login/mobile")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Sign in via mobile (returns tokens in body)" })
  @ApiBody({
    schema: {
      properties: { email: { type: "string" }, password: { type: "string" } },
    },
  })
  @ApiResponse({ status: 200, description: "Returns access and refresh tokens" })
  @ApiResponse({ status: 401, description: "Invalid credentials" })
  @ApiResponse({ status: 498, description: "Access token expired" })
  async loginMobile(
    @Body() body: { email: string; password: string },
    @Req() req: Request,
  ) {
    const ip = this.authService.getClientIp(req);
    const userAgent = req.get("user-agent") || undefined;
    return this.authService.signIn(body.email, body.password, ip, userAgent, "mobile");
  }

  @Public()
  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  @ApiCookieAuth("refresh_token")
  @ApiOperation({ summary: "Refresh tokens via cookie (web)" })
  @ApiResponse({ status: 200, description: "New tokens set in cookies" })
  @ApiResponse({ status: 401, description: "Invalid refresh token" })
  @ApiResponse({ status: 498, description: "Refresh token expired, login required" })
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const token =
      (req.cookies?.refresh_token as string) ??
      (req.headers["x-refresh-token"] as string);
    if (!token) {
      throw new UnauthorizedException("Missing refresh token");
    }
    const ip = this.authService.getClientIp(req);
    const userAgent = req.get("user-agent") || undefined;
    const tokens = await this.authService.refreshToken(token, ip, userAgent);
    this.authService.setAuthCookies(res, tokens);
    return { message: "Token refreshed successfully" };
  }

  @Public()
  @Post("refresh/mobile")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Refresh tokens via x-refresh-token header (mobile)" })
  @ApiHeader({ name: "x-refresh-token", description: "Refresh token", required: true })
  @ApiResponse({ status: 200, description: "Returns new access and refresh tokens" })
  @ApiResponse({ status: 401, description: "Invalid refresh token" })
  @ApiResponse({ status: 498, description: "Refresh token expired, login required" })
  async refreshMobile(
    @Req() req: Request,
    @Body() body: { refreshToken?: string },
  ) {
    const token = (req.headers["x-refresh-token"] as string) ?? body.refreshToken;
    if (!token) {
      throw new UnauthorizedException("Missing refresh token");
    }
    const ip = this.authService.getClientIp(req);
    const userAgent = req.get("user-agent") || undefined;
    return this.authService.refreshToken(token, ip, userAgent);
  }

  @Post("logout")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiCookieAuth("access_token")
  @ApiOperation({ summary: "Sign out user and clear auth cookies" })
  async logout(
    @GetCurrentUser() user: JwtPayloadWithSession,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logout(user.sub!, user.sessionId, user.jti, user.exp);
    this.authService.clearAuthCookies(res);
    return { message: "Logout successful" };
  }

  @Post("logout/mobile")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: "Sign out mobile user" })
  async mobileLogout(@GetCurrentUser() user: JwtPayloadWithSession) {
    await this.authService.logout(user.sub!, user.sessionId, user.jti, user.exp);
    return { message: "Logout successful" };
  }

  @Get("me")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiCookieAuth("access_token")
  @ApiOperation({ summary: "Get current user profile" })
  @ApiResponse({ status: 200, description: "Current user profile" })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  @ApiResponse({ status: 498, description: "Access token expired" })
  getMe(@GetCurrentUserId() userId: string) {
    return this.authService.getMe(userId);
  }

  @Get("check-auth")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: "Check if the current user is authenticated" })
  getCheckAuth() {
    return { authenticated: true };
  }

  @Get("sessions")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiCookieAuth("access_token")
  @ApiOperation({ summary: "List all active sessions" })
  async listSessions(@GetCurrentUser() user: JwtPayloadWithSession) {
    return this.authService.listSessions(user.sub!, user.sessionId);
  }

  @Delete("sessions/:id")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: "Revoke a specific session" })
  async revokeSession(
    @GetCurrentUserId() userId: string,
    @Param("id") sessionId: string,
  ) {
    await this.authService.revokeSession(userId, sessionId);
    return { message: "Session revoked successfully" };
  }

  @Public()
  @Get("health")
  @ApiOperation({ summary: "Health check" })
  health() {
    return { status: "ok" };
  }
}