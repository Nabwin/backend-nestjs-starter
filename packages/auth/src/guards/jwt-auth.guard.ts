import { ExecutionContext, HttpStatus, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";

import { IS_PUBLIC_KEY } from "../decorators/public.decorator";

const ACCESS_TOKEN_EXPIRED_CODE = "ACCESS_TOKEN_EXPIRED";

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }
    return super.canActivate(context);
  }

  handleRequest<TUser>(err: Error | null, user: TUser): TUser {
    if (err || !user) {
      if (err && err.name === "TokenExpiredError") {
        throw new UnauthorizedException({
          message: "Access token expired. Please refresh.",
          code: ACCESS_TOKEN_EXPIRED_CODE,
          statusCode: 498,
        });
      }
      throw err ?? new UnauthorizedException();
    }
    return user;
  }
}
