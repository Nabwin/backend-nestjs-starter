import type { JwtPayload } from "./jwt-payload.type";

export interface AuthenticatedUser extends JwtPayload {
  userId: string;
}
