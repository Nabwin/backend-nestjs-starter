import { createParamDecorator, ExecutionContext } from "@nestjs/common";

export const GetCurrentUserId = createParamDecorator(
  (_: undefined, ctx: ExecutionContext): string | null => {
    const request = ctx.switchToHttp().getRequest();
    return request.user?.sub ?? null;
  },
);
