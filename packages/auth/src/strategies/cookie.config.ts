import type { CustomCookieOptions } from "../types/custom-cookie-options.type";

export const DEFAULT_COOKIE_OPTIONS: CustomCookieOptions = {
  httpOnly: true,
  secure: true,
  path: "/",
  refreshTokenPath: "/api/v1/auth",
  sameSite: "none",
};

export const COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;