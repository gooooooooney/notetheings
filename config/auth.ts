import { compare } from "bcryptjs";
import CredentialsProvider from "next-auth/providers/credentials";
import GitHubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";

import type { NextAuthConfig } from "next-auth";

import { db } from "@/lib/db";
import { env } from "@/lib/env";
import { loginSchema } from "@/lib/validations";

export const authConfig: NextAuthConfig = {
  providers: [
    CredentialsProvider({
      async authorize(credentials) {
        const validatedFields = loginSchema.safeParse(credentials);

        if (validatedFields.success) {
          const user = validatedFields.data;

          const dbUser = await db.user.findFirst({
            where: {
              email: {
                equals: user.email,
              }
            }
          });

          if (dbUser && dbUser.password) {
            const isValid = await compare(user.password, dbUser.password);

            if (isValid) {
              return dbUser;
            }
          }
        }

        return null;
      },
    }),
  ],
};