import type { ToolCallEvent } from "../types/mcp.js";

// The capability that, once seen on any tool call, taints the session.
export const TAINT_CAPABILITY = "sees_untrusted_content";

// Tracks session-level taint: whether untrusted content has entered the
// session. Like TrifectaTracker, this is a pure class with no I/O and no
// Logger dependency — the caller owns audit writes.
//
// Taint is STICKY: once set, it never clears for the lifetime of the tracker
// (i.e. the session). See "Taint" in CLAUDE.md.
export class TaintTracker {
  private _tainted = false;

  // Sets the sticky taint flag if the call exposed the session to untrusted
  // content. Idempotent once tainted.
  observe(event: ToolCallEvent): void {
    if (event.capabilities.includes(TAINT_CAPABILITY)) {
      this._tainted = true;
    }
  }

  isTainted(): boolean {
    return this._tainted;
  }
}
