// JSON-RPC 2.0 base types for MCP messages

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: string | number;
  method: string;
  params?: unknown;
}

export interface JsonRpcNotification {
  jsonrpc: "2.0";
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export type JsonRpcMessage =
  | JsonRpcRequest
  | JsonRpcNotification
  | JsonRpcResponse;

export type MessageDirection = "client->server" | "server->client";

export interface InterceptedMessage {
  direction: MessageDirection;
  raw: string;
  parsed: JsonRpcMessage;
  timestamp: string;
  sessionId: string;
  server: string;
}

// A single tool invocation, enriched with the capability tags resolved by the
// v0.1 capability tagger, presented to the policy engine for evaluation.
// This is the engine's input contract (see src/policy/engine.ts).
export interface ToolCallEvent {
  // Tool name as advertised by the server, e.g. "send_message".
  tool: string;
  // Originating MCP server name, e.g. "gmail".
  server: string;
  // Call-level capability tags from the tagger, e.g. ["can_exfiltrate"].
  capabilities: string[];
  // Whether the session has completed the lethal trifecta. Rides on the event
  // so the pure engine never has to reach for session state. Defaults to false
  // until the trifecta tracker (a later issue) populates it.
  sessionTrifecta?: boolean;
  // Whether the session is tainted — untrusted content has entered it. Rides
  // on the event for the same reason as sessionTrifecta: the pure engine never
  // reaches for session state. Populated by the taint tracker; defaults to
  // false in evaluation.
  sessionTainted?: boolean;
}
