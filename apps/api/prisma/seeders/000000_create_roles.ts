import type { PrismaClient } from "../../src/db/generated/client";

export const up = async (prisma: PrismaClient) => {
  const rolesCount = await prisma.role.count();
  if (rolesCount) {
    return;
  }

  await prisma.role.createMany({
    data: [
      { name: "Admin", slug: "admin", permissions: ["*"] },
      { name: "User", slug: "user", permissions: [] },
    ],
  });
};