import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

export const KNOWN_CAPABILITIES = [
  "reads_private_data",
  "sees_untrusted_content",
  "can_exfiltrate",
  "can_execute_code",
  "can_modify_files",
  "can_send_messages",
  "touches_credentials",
] as const;

const CapabilitySchema = z.enum(KNOWN_CAPABILITIES);

const ToolPatternSchema = z.object({
  match: z.string().min(1),
  tags: z.array(CapabilitySchema),
});

export type ToolPattern = z.infer<typeof ToolPatternSchema>;

const PolicySchema = z.object({
  version: z.number(),
  name: z.string(),
  capabilities: z.array(CapabilitySchema),
  tools: z.array(ToolPatternSchema),
});

export type Policy = z.infer<typeof PolicySchema>;

export function loadPolicy(filePath: string): Policy {
  const resolved = filePath.startsWith("~")
    ? path.join(os.homedir(), filePath.slice(1))
    : filePath;

  const raw = fs.readFileSync(resolved, "utf8");
  const parsed = parseYaml(raw);

  const result = PolicySchema.safeParse(parsed);
  if (!result.success) {
    throw new Error(`Invalid policy at ${filePath}: ${result.error.message}`);
  }
  return result.data;
}
