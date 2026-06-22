export const DEVICE_TYPE = {
  WEB: "web",
  MOBILE: "mobile",
} as const;

export const OAUTH_METHOD = {
  GOOGLE: "google",
  FACEBOOK: "facebook",
  LINKEDIN: "linkedin",
  APPLE: "apple",
} as const;
export type OAuthMethod = (typeof OAUTH_METHOD)[keyof typeof OAUTH_METHOD];