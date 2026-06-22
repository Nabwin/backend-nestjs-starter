import "dotenv/config";
import { readdirSync } from "fs";
import { join } from "path";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../src/db/generated/client";

type SeederUpFunction = (prisma: PrismaClient) => any;

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  throw new Error("DATABASE_URL is not set");
}

const adapter = new PrismaPg({ connectionString });
const prisma = new PrismaClient({ adapter });

async function main() {
  const seedersDir = join(__dirname, "seeders");
  const files = readdirSync(seedersDir)
    .filter((file) => file.endsWith(".ts"))
    .sort((a, b) => {
      const orderA = Number(a.split("_")[0]);
      const orderB = Number(b.split("_")[0]);
      return orderA - orderB;
    });

  for (const file of files) {
    const filePath = join(seedersDir, file);
    const { up }: { up: SeederUpFunction } = await import(filePath);
    if (!up) {
      throw new Error(
        `Seeder "${file}" is missing an exported "up" function`,
      );
    }
    await up(prisma);
  }

  console.log("Seed completed");
}

main()
  .catch((error) => {
    console.error("Seeding failed:", error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });