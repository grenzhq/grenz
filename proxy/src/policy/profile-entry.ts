/**
 * Shared, dependency-light definitions for a per-agent policy profile as it
 * travels in the signed bundle. Its own leaf module so both distribution/ and
 * policy/ import it without either pulling in config/schema.ts (import cycle).
 */
import { z } from "zod";

/** A profile name: lowercase start, then lowercase/digit/underscore/dash, <=64. */
export const PROFILE_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/** Per-profile policy YAML cap. The bundle schema is walked BEFORE the signature
 *  is verified, so an unauthenticated body must not force an unbounded parse. */
export const MAX_PROFILE_POLICY_BYTES = 65536;

/** One profile as carried in a bundle: a name + its policy YAML (grants only are
 *  used by the merge; see policy/merge.ts). */
export interface ProfileEntry {
  readonly name: string;
  readonly policy: string;
}

/** Validates one bundle profile entry. Shared by the signer (sign-time guard) and
 *  the verifier (load-time guard) so the two cannot drift. */
export const profileEntrySchema: z.ZodType<ProfileEntry> = z
  .object({
    name: z.string().regex(PROFILE_NAME_RE),
    policy: z.string().max(MAX_PROFILE_POLICY_BYTES),
  })
  .strict();
