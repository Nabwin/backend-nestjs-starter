import { z } from "zod";

export const jwtExpirySchema = z
  .string()
  .refine(
    (val) => ["s", "m", "h", "d", "w"].includes(val.slice(-1)),
    "Invalid time unit. Use s (seconds), m (minutes), h (hours), d (days), or w (weeks).",
  )
  .refine(
    (val) => !isNaN(parseInt(val.slice(0, -1))),
    "Invalid time value. Must be a number followed by a valid time unit.",
  );

export const baseEnvSchema = z.object({
  JWT_SECRET: z.string(),
  JWT_REFRESH_SECRET: z.string(),
  JWT_EXPIRES_IN: jwtExpirySchema,
  JWT_REFRESH_EXPIRES_IN: jwtExpirySchema,
});

export type EnvValidationType = Required<z.infer<typeof baseEnvSchema>>;
