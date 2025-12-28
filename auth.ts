
import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { z } from "zod";
import bcrypt from "bcryptjs";
import prisma from "./lib/prisma";

const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

export const { handlers, auth, signIn, signOut } = NextAuth({
  adapter: PrismaAdapter(prisma),
  session: { strategy: "database" },
  providers: [
    Credentials({
      credentials: { email: {}, password: {} },
      authorize: async (raw) => {
        const { email, password } = credentialsSchema.parse(raw);

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user?.passwordHash) return null;

        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return null;

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        } as any;
      },
    }),
  ],
  callbacks: {
    session: async ({ session, user }) => {
      // Exponemos lo mínimo útil al frontend
      (session.user as any).id = user.id;
      (session.user as any).role = (user as any).role;
      (session.user as any).subscriptionStatus = (user as any).subscriptionStatus;
      return session;
    },
  },
});
