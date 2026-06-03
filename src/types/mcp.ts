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
}
