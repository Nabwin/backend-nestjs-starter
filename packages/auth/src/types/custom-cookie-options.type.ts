import type { CookieOptions } from "express";

export type CustomCookieOptions = CookieOptions & {
  refreshTokenPath?: string;
};