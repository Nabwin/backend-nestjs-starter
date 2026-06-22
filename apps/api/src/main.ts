import { Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import cookieParser from "cookie-parser";

import { AppModule } from "./app.module";
import type { EnvValidationType } from "./env.validation";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService<EnvValidationType, true>);
  const logger = new Logger("Bootstrap");

  app.setGlobalPrefix("api/v1");
  app.use(cookieParser());

  app.enableCors({
    origin: config.get("FRONTEND_URL"),
    credentials: true,
  });

  const swaggerConfig = new DocumentBuilder()
    .setTitle(config.get("APP_NAME"))
    .setDescription("NestJS + Turborepo monorepo starter template")
    .setVersion("1.0")
    .addBearerAuth()
    .addCookieAuth("access_token")
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup("api-docs", app, document);

  const port = config.get("PORT", 3000);
  const appName = config.get("APP_NAME");
  const env = config.get("APP_ENV");

  await app.listen(port);

  logger.log(`🚀 ${appName} running on http://localhost:${port}/api/v1 (${env})`);
  logger.log(`📚 Swagger docs at http://localhost:${port}/api-docs`);
}
void bootstrap();