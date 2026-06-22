import { OAuthProvider } from "src/db/generated/client";

export { OAuthProvider };

export interface OAuthProfile {
  provider: OAuthProvider;
  providerId: string;
  email: string;
  firstName?: string;
  lastName?: string;
  profilePicture?: string;
  isEmailVerified?: boolean;
}