import { hash } from "bcrypt";
import type { PrismaClient } from "../../src/db/generated/client";

const SALT_ROUNDS = 12;

export const up = async (prisma: PrismaClient) => {
  const password = await hash("password123", SALT_ROUNDS);

  const userRole = await prisma.role.findUniqueOrThrow({
    where: { slug: "user" },
  });
  const adminRole = await prisma.role.findUniqueOrThrow({
    where: { slug: "admin" },
  });

  await prisma.user.upsert({
    where: { email: "admin@example.com" },
    update: {},
    create: {
      email: "admin@example.com",
      password,
      fullName: "Admin User",
      roleId: adminRole.id,
    },
  });

  await prisma.user.upsert({
    where: { email: "user@example.com" },
    update: {},
    create: {
      email: "user@example.com",
      password,
      fullName: "Test User",
      roleId: userRole.id,
    },
  });
};