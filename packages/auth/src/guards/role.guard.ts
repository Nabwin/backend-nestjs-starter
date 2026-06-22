import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  SetMetadata,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";

import type { AuthenticatedUser } from "../types";

export const ALLOWED_ROLES_KEY = "allowedRoles";

export const AllowedRoles = (...roles: string[]) => SetMetadata(ALLOWED_ROLES_KEY, roles);

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ALLOWED_ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user: AuthenticatedUser | undefined = request.user;

    if (!user) {
      throw new ForbiddenException("Authentication required");
    }

    if (!requiredRoles.includes(user.role)) {
      throw new ForbiddenException({
        statusCode: 403,
        message: "You are not authorized to access this resource",
        error: "Forbidden",
      });
    }

    return true;
  }
}
