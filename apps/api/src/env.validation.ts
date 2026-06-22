import { baseEnvSchema } from "@repo/auth/strategies/types";
import { z } from "zod";

export { jwtExpirySchema } from "@repo/auth/strategies/types";

export const envValidationSchema = baseEnvSchema.extend({
  APP_ENV: z.enum(["development", "production"]).default("development"),

  PORT: z.coerce.number().optional(),

  APP_NAME: z.string().default("Backend Template"),
  FRONTEND_URL: z.string().default("http://localhost:3000"),

  SWAGGER_AUTH_USER: z.string().optional(),
  SWAGGER_AUTH_PASSWORD: z.string().optional(),
});

export type EnvValidationType = Required<z.infer<typeof envValidationSchema>>;

declare global {
  namespace NodeJS {
    interface ProcessEnv extends Omit<EnvValidationType, "PORT"> {
      PORT: string;
    }
  }
}
