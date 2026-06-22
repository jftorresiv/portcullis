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

const WhenConditionSchema = z.object({
  session_has_capabilities: z
    .object({ all: z.array(z.string()) })
    .optional(),
  session_tainted: z.boolean().optional(),
  trifecta: z.boolean().optional(),
  tool_call: z
    .object({
      has_capability: z.string().optional(),
      tool_matches: z.array(z.string()).optional(),
      arguments_match: z.array(z.string()).optional(),
    })
    .optional(),
  tool_registration: z
    .object({ description_matches: z.array(z.string()).optional() })
    .optional(),
  server: z.string().optional(),
  session_metrics: z.record(z.string(), z.unknown()).optional(),
}).optional();

const PolicyRuleSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  when: WhenConditionSchema,
  action: z.enum(["allow", "block", "warn", "confirm"]),
  message: z.string().optional(),
});

export type WhenCondition = NonNullable<z.infer<typeof WhenConditionSchema>>;
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

const PolicySchema = z.object({
  version: z.number(),
  name: z.string(),
  capabilities: z.array(CapabilitySchema),
  tools: z.array(ToolPatternSchema),
  rules: z.array(PolicyRuleSchema).optional(),
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
