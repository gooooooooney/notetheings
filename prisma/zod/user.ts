import * as z from "zod"
import { CompleteWorkspace, relatedWorkspaceSchema } from "./index"

export const userSchema = z.object({
  id: z.string(),
  username: z.string(),
  imageUrl: z.string(),
  email: z.string(),
  /**
   * @password
   * @omit
   */
  password: z.string(),
  externalUserId: z.string(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export interface CompleteUser extends z.infer<typeof userSchema> {
  workspaces: CompleteWorkspace[]
}

/**
 * relatedUserSchema contains all relations on your model in addition to the scalars
 *
 * NOTE: Lazy required in case of potential circular dependencies within schema
 */
export const relatedUserSchema: z.ZodSchema<CompleteUser> = z.lazy(() => userSchema.extend({
  workspaces: relatedWorkspaceSchema.array(),
}))
