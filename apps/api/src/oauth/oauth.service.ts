import { BadRequestException, Injectable } from "@nestjs/common";
import { createHash, randomBytes } from "crypto";

import { UserStatus } from "src/db/generated/enums";
import { PrismaService } from "src/db/prisma.service";
import type { OAuthProfile } from "src/oauth/types/oauth-profile.type";

@Injectable()
export class OAuthService {
  constructor(private readonly prisma: PrismaService) {}

  async upsertOAuthUser(profile: OAuthProfile) {
    const { provider, providerId, email, firstName, lastName, profilePicture } = profile;

    const existingAccount = await this.prisma.oAuthAccount.findUnique({
      where: { provider_providerId: { provider, providerId } },
      include: { user: { include: { role: true } } },
    });

    if (existingAccount) {
      if (existingAccount.user.status !== UserStatus.ACTIVE) {
        throw new BadRequestException("Account is suspended or banned");
      }
      return {
        id: existingAccount.user.id,
        email: existingAccount.user.email,
        role: existingAccount.user.role?.slug ?? "user",
      };
    }

    if (email) {
      const existingUser = await this.prisma.user.findUnique({
        where: { email },
        include: { role: true },
      });

      if (existingUser) {
        await this.prisma.oAuthAccount.create({
          data: { provider, providerId, userId: existingUser.id },
        });

        return {
          id: existingUser.id,
          email: existingUser.email,
          role: existingUser.role?.slug ?? "user",
        };
      }
    }

    const defaultRole = await this.prisma.role.findFirst({ where: { slug: "user" } });
    const fullName = [firstName, lastName].filter(Boolean).join(" ") || email;

    const newUser = await this.prisma.$transaction(async (trx) => {
      return trx.user.create({
        data: {
          email,
          fullName,
          avatar: profilePicture ?? null,
          status: UserStatus.ACTIVE,
          password: this.generateSecurePassword(),
          roleId: defaultRole?.id ?? null,
          OAuthAccounts: {
            create: { provider, providerId },
          },
        },
        include: { role: true },
      });
    });

    return {
      id: newUser.id,
      email: newUser.email,
      role: newUser.role?.slug ?? "user",
    };
  }

  private generateSecurePassword(): string {
    return createHash("sha256").update(randomBytes(32)).digest("hex");
  }
}