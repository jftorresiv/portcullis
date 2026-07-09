import type { Logger } from "../audit/logger.js";

export interface KillSwitchContext {
  sessionId: string;
  server: string;
}

/**
 * Session-level freeze. When frozen, the proxy must stop forwarding any
 * client->server traffic until reset() is called. Safe to activate/reset
 * before configure() runs — the frozen flag flips immediately regardless of
 * whether audit logging is wired up yet; only the log write is skipped.
 */
export class KillSwitch {
  private frozen = false;
  private logger: Logger | null = null;
  private context: KillSwitchContext | null = null;

  configure(logger: Logger, context: KillSwitchContext): void {
    this.logger = logger;
    this.context = context;
  }

  isFrozen(): boolean {
    return this.frozen;
  }

  activate(): void {
    this.frozen = true;
    this.log("kill_switch_activated");
  }

  reset(): void {
    this.frozen = false;
    this.log("kill_switch_reset");
  }

  private log(type: "kill_switch_activated" | "kill_switch_reset"): void {
    if (this.logger === null || this.context === null) return;
    this.logger
      .append({
        timestamp: new Date().toISOString(),
        session_id: this.context.sessionId,
        direction: "client_to_server",
        server: this.context.server,
        method: "kill_switch",
        message: { event: type },
        type,
      })
      .catch((err: unknown) => {
        process.stderr.write(`[portcullis] audit log write failed: ${err}\n`);
      });
  }
}

export const killSwitch = new KillSwitch();
