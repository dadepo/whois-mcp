export type ToolResult<T> =
  | {
      ok: true;
      data: T;
    }
  | {
      ok: false;
      error: string;
      detail: string;
    };

export interface ContactInfo {
  handle?: string;
  name?: unknown;
  person?: unknown;
  role?: unknown;
  emails: unknown[];
  phones: unknown[];
  remarks?: unknown[];
  address?: unknown;
  type?: unknown;
}

export interface McpJsonToolResult<T = unknown> {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  structuredContent: T;
  isError?: boolean;
}

export function toMcpResult<T extends ToolResult<unknown>>(result: T): McpJsonToolResult<T> {
  return {
    content: [{ type: "text", text: JSON.stringify(result) }],
    structuredContent: result
  };
}
