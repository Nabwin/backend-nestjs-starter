import { Injectable, OnModuleInit } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";

import type { EnvValidationType } from "src/env.validation";
import { OAUTH_METHOD, type OAuthMethod } from "src/oauth/types/enums";

const METHOD_KEYS: Record<OAuthMethod, keyof EnvValidationType> = {
  [OAUTH_METHOD.GOOGLE]: "GOOGLE_CLIENT_ID",
  [OAUTH_METHOD.FACEBOOK]: "FACEBOOK_CLIENT_ID",
  [OAUTH_METHOD.LINKEDIN]: "LINKEDIN_CLIENT_ID",
  [OAUTH_METHOD.APPLE]: "APPLE_CLIENT_ID",
};

@Injectable()
export class OAuthProvidersService implements OnModuleInit {
  private enabled: Set<OAuthMethod> = new Set();

  constructor(private readonly config: ConfigService<EnvValidationType, true>) {}

  onModuleInit() {
    const configured = this.config.get("ENABLED_OAUTH_METHODS");
    const allValues = Object.values(OAUTH_METHOD) as string[];

    for (const raw of configured) {
      const method = allValues.find((v) => v === raw) as OAuthMethod | undefined;
      if (method && METHOD_KEYS[method] && this.config.get(METHOD_KEYS[method])) {
        this.enabled.add(method);
      }
    }
  }

  isEnabled(provider: OAuthMethod): boolean {
    return this.enabled.has(provider);
  }

  getEnabled(): OAuthMethod[] {
    return [...this.enabled];
  }
}