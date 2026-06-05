import * as crypto from "node:crypto";
import { startDashboard } from "./server.js";

const LOG_PATH = process.env["PORTCULLIS_AUDIT_LOG"] ?? "~/.portcullis/audit.jsonl";
const REQUIRE_TOKEN = process.env["PORTCULLIS_REQUIRE_TOKEN"] === "1";
const ENV_TOKEN = process.env["PORTCULLIS_DASHBOARD_TOKEN"];

// Token is used if: explicitly provided via env, or require_token flag is set
// (in which case a random one is generated and printed to stderr).
const token = ENV_TOKEN ?? (REQUIRE_TOKEN ? crypto.randomBytes(16).toString("hex") : undefined);

startDashboard({ logPath: LOG_PATH, ...(token !== undefined ? { token } : {}) }).catch((err: unknown) => {
  process.stderr.write(`[portcullis] dashboard failed to start: ${err}\n`);
  process.exit(1);
});
