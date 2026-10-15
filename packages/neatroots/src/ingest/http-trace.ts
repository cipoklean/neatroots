import crypto from "node:crypto";
import type { ResourceSpansBatch } from "../otlp/types.js";
import { toBatches, toNs, type SpanNode } from "./build.js";

// The Neatlogs HTTP trace API (POST /v1/trace): one JSON tree per trace, no ids, nesting in
// `children`. The Neatlogs Browser SDK sends the same shape. Field names follow the public docs.

export interface HttpTraceNode {
  name: string;
  project?: string;
  kind?: string;
  input?: unknown;
  output?: unknown;
  model?: string;
  provider?: string;
  tokens?: { prompt?: number; completion?: number; total?: number };
  query?: unknown;
  documents?: unknown;
  tool_name?: string;
  passed?: boolean;
  score?: number;
  status?: string;
  error?: string;
  start?: string | number;
  end?: string | number;
  duration_ms?: number;
  metadata?: Record<string, unknown>;
  attributes?: Record<string, unknown>;
  logs?: { level?: string; message: string; timestamp?: string }[];
  children?: HttpTraceNode[];
  session_id?: string;
  sessionId?: string;
  end_user_id?: string;
  endUserId?: string;
  user_id?: string;
  tags?: string[];
}

export class HttpTraceError extends Error {
  constructor(
    message: string,
    readonly details: Record<string, string>,
  ) {
    super(message);
  }
}

// Deeply-nested children would overflow the recursive validate()/walk() stack.
// Real traces are shallow; cap well above any genuine depth so a pathological
// payload becomes a clean validation error instead of a crash.
const MAX_DEPTH = 256;

function validate(node: unknown, path: string, errors: Record<string, string>, depth = 0): void {
  if (!node || typeof node !== "object" || Array.isArray(node)) {
    errors[path || "body"] = "must be an object";
    return;
  }
  if (depth > MAX_DEPTH) {
    errors[`${path}children`] = `nested too deep (max ${MAX_DEPTH})`;
    return;
  }
  const n = node as Record<string, unknown>;
  if (typeof n.name !== "string" || !n.name.trim()) errors[`${path}name`] = "required";
  if (n.children !== undefined) {
    if (!Array.isArray(n.children)) errors[`${path}children`] = "must be an array";
    else n.children.forEach((c, i) => validate(c, `${path}children[${i}].`, errors, depth + 1));
  }
  if (n.tokens !== undefined) {
    if (typeof n.tokens !== "object" || n.tokens === null) errors[`${path}tokens`] = "must be an object";
    else {
      const t = n.tokens as Record<string, unknown>;
      for (const k of ["prompt", "completion", "total"]) {
        if (t[k] !== undefined && (typeof t[k] !== "number" || !Number.isFinite(t[k] as number))) errors[`${path}tokens.${k}`] = "must be a finite number";
      }
    }
  }
  if (n.score !== undefined && (typeof n.score !== "number" || !Number.isFinite(n.score))) errors[`${path}score`] = "must be a finite number";
  if (n.duration_ms !== undefined && (typeof n.duration_ms !== "number" || !Number.isFinite(n.duration_ms))) errors[`${path}duration_ms`] = "must be a finite number";
  if (n.status !== undefined && !["OK", "ERROR", "ok", "error"].includes(String(n.status))) errors[`${path}status`] = "must be OK or ERROR";
}

/**
 * A node's kind when it doesn't say, in the documented order: tool_name, passed/score, model/tokens,
 * query/documents; then the root is a workflow, a node with children a chain, and a bare leaf a tool.
 */
function inferKind(n: HttpTraceNode, isRoot: boolean): string {
  if (n.tool_name) return "tool";
  if (n.passed !== undefined || n.score !== undefined) return "guardrail";
  if (n.model || n.tokens) return "llm";
  if (n.query !== undefined || n.documents !== undefined) return "retriever";
  if (isRoot) return "workflow";
  return n.children?.length ? "chain" : "tool";
}

/** Converts one HTTP trace into OTLP spans. Throws HttpTraceError with field details when it's malformed. */
export function httpTraceToBatches(body: unknown, fallbackProject = "http"): { batches: ResourceSpansBatch[]; traceId: string; spans: number } {
  const errors: Record<string, string> = {};
  validate(body, "", errors);
  if (Object.keys(errors).length) throw new HttpTraceError("Validation error", errors);
  const root = body as HttpTraceNode;
  const traceId = crypto.randomBytes(16).toString("hex");
  const nodes: SpanNode[] = [];
  const sessionId = root.session_id ?? root.sessionId;
  const userId = root.end_user_id ?? root.endUserId ?? root.user_id;
  const nowNs = BigInt(Date.now()) * 1_000_000n;

  // Returns the node's start and end, so a parent without times can span its children.
  const walk = (n: HttpTraceNode, parent: string | null, startFallback: bigint): { start: bigint; end: bigint } => {
    const spanId = crypto.randomBytes(8).toString("hex");
    const ownStart = toNs(n.start);
    let start = ownStart ?? startFallback;
    let cursor = start;
    const childEnds: bigint[] = [];
    const index = nodes.length;
    nodes.push({ traceId, spanId, parentSpanId: parent, name: n.name, start: Number(start) } as SpanNode);
    for (const c of n.children ?? []) {
      const { start: childStart, end } = walk(c, spanId, cursor);
      // A parent without its own start begins with its earliest child, not at ingest time.
      if (ownStart === undefined && childStart < start) start = childStart;
      childEnds.push(end);
      cursor = end;
    }
    let end = toNs(n.end);
    if (end === undefined && typeof n.duration_ms === "number") {
      const durNs = Math.round(n.duration_ms * 1e6);
      // Guard: a huge (finite) duration_ms can still overflow to Infinity; only apply a finite result.
      if (Number.isFinite(durNs)) end = start + BigInt(durNs);
    }
    if (end === undefined) end = childEnds.length ? childEnds.reduce((a, b) => (b > a ? b : a)) : start;
    const kind = n.kind ?? inferKind(n, !parent);
    const attributes: Record<string, unknown> = { ...(n.attributes ?? {}) };
    for (const [k, v] of Object.entries(n.metadata ?? {})) attributes[`neatlogs.metadata.${k}`] = v;
    if (n.passed !== undefined) attributes["neatlogs.guardrail.passed"] = n.passed;
    if (n.score !== undefined) attributes["neatlogs.guardrail.score"] = n.score;
    if (!parent && root.tags?.length) attributes["neatlogs.tags"] = root.tags.join(",");
    nodes[index] = {
      traceId,
      spanId,
      parentSpanId: parent,
      name: n.name,
      kind,
      start: Number(start),
      end: Number(end),
      // A guardrail that didn't pass (passed: false) is an error span, as the HTTP trace docs say.
      status: n.status?.toUpperCase() ?? (n.error || n.passed === false ? "ERROR" : "OK"),
      error: n.error ?? null,
      input: n.input ?? n.query,
      output: n.output ?? n.documents,
      model: n.model,
      provider: n.provider,
      promptTokens: n.tokens?.prompt,
      completionTokens: n.tokens?.completion,
      totalTokens: n.tokens?.total,
      toolName: n.tool_name,
      sessionId: sessionId ?? null,
      userId: userId ?? null,
      attributes,
      logs: n.logs,
    };
    // Number() keeps ns precision only to ~1 µs; that is plenty for display and ordering.
    return { start, end };
  };
  walk(root, null, nowNs);
  // SpanNode times are numbers in ns here; buildSpan reads values above 1e17 as ns.
  const batches = toBatches(nodes, { project: root.project ?? fallbackProject, source: "http" });
  return { batches, traceId, spans: nodes.length };
}
