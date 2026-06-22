import { baseEnvSchema } from "@repo/auth/strategies/types";
import { z } from "zod";

export { jwtExpirySchema } from "@repo/auth/strategies/types";

const oauthMethodEnum = z.enum(["google", "facebook", "linkedin", "apple"]);

const oauthMethodsSchema = z
  .string()
  .optional()
  .default("")
  .transform((val) =>
    val
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  )
  .pipe(z.array(oauthMethodEnum));

export const envValidationSchema = baseEnvSchema.extend({
  APP_ENV: z.enum(["development", "production"]).default("development"),

  PORT: z.coerce.number().optional(),

  DATABASE_URL: z.string(),
  REDIS_URL: z.string().default("redis://127.0.0.1:6379"),

  APP_NAME: z.string().default("Backend Template"),
  FRONTEND_URL: z.string().default("http://localhost:3000"),
  BACKEND_URL: z.string().default("http://localhost:3001"),

  SWAGGER_AUTH_USER: z.string().optional(),
  SWAGGER_AUTH_PASSWORD: z.string().optional(),

  ENABLED_OAUTH_METHODS: oauthMethodsSchema,

  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  FACEBOOK_CLIENT_ID: z.string().optional(),
  FACEBOOK_CLIENT_SECRET: z.string().optional(),
  LINKEDIN_CLIENT_ID: z.string().optional(),
  LINKEDIN_CLIENT_SECRET: z.string().optional(),
  APPLE_CLIENT_ID: z.string().optional(),
  APPLE_TEAM_ID: z.string().optional(),
  APPLE_KEY_ID: z.string().optional(),
  APPLE_PRIVATE_KEY_PATH: z.string().optional(),
  APPLE_BUNDLE_ID: z.string().optional(),
});

export type EnvValidationType = Required<z.infer<typeof envValidationSchema>>;

declare global {
  namespace NodeJS {
    interface ProcessEnv extends Omit<EnvValidationType, "PORT"> {
      PORT: string;
    }
  }
}