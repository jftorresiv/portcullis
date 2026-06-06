import { CapabilityRegistry } from "./registry.js";

let _registry = new CapabilityRegistry([]);

export function init(registry: CapabilityRegistry): void {
  _registry = registry;
}

export function tagTool(serverName: string, toolName: string): string[] {
  return _registry.tag(serverName, toolName);
}
