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

// A tool as advertised in an MCP `tools/list` response. Only the fields the
// injection scanner (issue #22) reads are typed here; servers may send more.
export interface Tool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

// One prior tool call in a session, as tracked by the proxy for windowed
// session-rate metrics (issue #28). Carries only what the engine's
// `session_metrics` condition needs: when the call happened and what
// capabilities it exercised.
export interface SessionCallRecord {
  // Wall-clock time of the call, in epoch milliseconds (Date.now()).
  timestamp: number;
  // Call-level capability tags for that call, e.g. ["reads_private_data"].
  capabilities: string[];
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
  // Pattern keys (warn+critical only) from the injection scanner's cached scan
  // of the tools/list response, for the tool being called. Populated by the
  // proxy at tool-call time (issue #22). Absent when no findings apply.
  descriptionFindings?: string[];
  // The raw arguments object of the tool call (MCP `params.arguments`), passed
  // through untyped from the wire. Consumed by the engine's `arguments_match`
  // condition, which JSON-serializes it and tests configured regexes against
  // the result. Optional: absent when the call carried no arguments, in which
  // case the engine treats it as `{}`.
  arguments?: unknown;
  // A slice of the session's recent tool-call history, supplied by the proxy so
  // the engine's `session_metrics` condition can count calls within a time
  // window without reaching for session state. The current call is NOT included
  // (the proxy appends it only after evaluation). Absent or empty means the
  // metric condition cannot fire.
  sessionCallHistory?: SessionCallRecord[];
}
