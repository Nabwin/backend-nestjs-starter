import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";

import { AppController } from "src/app.controller";
import { AppService } from "src/app.service";
import { AuthModule } from "src/auth/auth.module";
import { PrismaModule } from "src/db/prisma.module";
import { envValidationSchema } from "src/env.validation";
import { OAuthModule } from "src/oauth/oauth.module";
import { RedisModule } from "src/redis/redis.module";

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validate: (config) => envValidationSchema.parse(config),
    }),
    PrismaModule,
    RedisModule,
    AuthModule,
    OAuthModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}