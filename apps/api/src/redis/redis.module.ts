import { RedisModule as NestRedisModule } from "@nestjs-modules/ioredis";
import { Global, Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";

import type { EnvValidationType } from "../env.validation";
import { SessionManagerService } from "./session-manager.service";

@Global()
@Module({
  imports: [
    NestRedisModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService<EnvValidationType, true>) => ({
        type: "single",
        url: configService.get<string>("REDIS_URL") || "redis://127.0.0.1:6379",
      }),
    }),
  ],
  providers: [SessionManagerService],
  exports: [SessionManagerService],
})
export class RedisModule {}