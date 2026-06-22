import { createParamDecorator, ExecutionContext } from "@nestjs/common";

import type { JwtPayload } from "../types";

export const GetCurrentUser = createParamDecorator(
  (data: keyof JwtPayload | undefined, ctx: ExecutionContext): JwtPayload | null => {
    const request = ctx.switchToHttp().getRequest();
    if (data) {
      return request.user?.[data] ?? null;
    }
    return request.user ?? null;
  },
);
