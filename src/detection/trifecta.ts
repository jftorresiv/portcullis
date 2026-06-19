export const TRIFECTA_LEGS = [
  "reads_private_data",
  "sees_untrusted_content",
  "can_exfiltrate",
] as const;

export interface TrifectaState {
  capabilities: ReadonlySet<string>;
  triggered: boolean;
  justTriggered: boolean;
}

export class TrifectaTracker {
  private readonly accumulated = new Set<string>();
  private _triggered = false;

  observe(capabilities: string[]): TrifectaState {
    for (const cap of capabilities) {
      this.accumulated.add(cap);
    }

    const wasTriggered = this._triggered;
    this._triggered = TRIFECTA_LEGS.every((leg) => this.accumulated.has(leg));
    const justTriggered = this._triggered && !wasTriggered;

    return {
      capabilities: this.accumulated,
      triggered: this._triggered,
      justTriggered,
    };
  }

  isTriggered(): boolean {
    return this._triggered;
  }

  getCapabilities(): ReadonlySet<string> {
    return this.accumulated;
  }
}
