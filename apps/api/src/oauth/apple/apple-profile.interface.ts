export interface AppleProfile {
  id: string;
  email?: string;
  emailVerified?: boolean;
  name?: {
    firstName?: string;
    lastName?: string;
  };
}