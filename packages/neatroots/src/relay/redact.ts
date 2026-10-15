import type { AnyValue, KeyValue, ResourceSpansBatch } from "../otlp/types.js";

export interface RedactionRule {
  kind: string;
  re: RegExp;
}

export const BUILTIN_RULES: RedactionRule[] = [
  { kind: "private_key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { kind: "api_key", re: /\b(sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b/g },
  { kind: "bearer_token", re: /\b(Bearer\s+)[A-Za-z0-9._~+/-]{20,}=*/gi },
  { kind: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { kind: "phone", re: /(?<![\w.])\+?(?:\d{1,3}[\s.-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\w.])/g },
];

export function compileRules(userPatterns: string[]): RedactionRule[] {
  const user: RedactionRule[] = [];
  for (const p of userPatterns) {
    try {
      user.push({ kind: "custom", re: new RegExp(p, "g") });
    } catch {
      /* ignore invalid user patterns; they are validated when saved */
    }
  }
  return [...BUILTIN_RULES, ...user];
}

export interface RedactionHit {
  kind: string;
  where: string;
  sample: string;
}

function mask(s: string): string {
  if (s.length <= 6) return "•".repeat(s.length);
  return s.slice(0, 3) + "•".repeat(Math.min(12, s.length - 5)) + s.slice(-2);
}

export function redactString(s: string, rules: RedactionRule[], where: string, hits: RedactionHit[]): string {
  let out = s;
  for (const r of rules) {
    r.re.lastIndex = 0;
    out = out.replace(r.re, (m: string, ...groups: unknown[]) => {
      // Keep a captured "Bearer " prefix readable.
      const prefix = r.kind === "bearer_token" && typeof groups[0] === "string" ? (groups[0] as string) : "";
      hits.push({ kind: r.kind, where, sample: mask(m) });
      return `${prefix}[redacted:${r.kind}]`;
    });
  }
  return out;
}

function redactValue(v: AnyValue, rules: RedactionRule[], where: string, hits: RedactionHit[]): AnyValue {
  if ("stringValue" in v) return { stringValue: redactString(v.stringValue, rules, where, hits) };
  if ("arrayValue" in v) return { arrayValue: { values: v.arrayValue.values.map((x) => redactValue(x, rules, where, hits)) } };
  if ("kvlistValue" in v) return { kvlistValue: { values: redactKvs(v.kvlistValue.values, rules, where, hits) } };
  return v;
}

function redactKvs(kvs: KeyValue[], rules: RedactionRule[], where: string, hits: RedactionHit[]): KeyValue[] {
  return kvs.map((kv) => ({ key: kv.key, value: redactValue(kv.value, rules, `${where} ${kv.key}`, hits) }));
}

/** Returns redacted copies of the batches and every redaction made. */
export function redactBatches(batches: ResourceSpansBatch[], rules: RedactionRule[]): { batches: ResourceSpansBatch[]; hits: RedactionHit[] } {
  const hits: RedactionHit[] = [];
  const out = batches.map((b) => ({
    resource: { ...b.resource, attributes: redactKvs(b.resource.attributes, rules, "resource", hits) },
    scope: b.scope.attributes ? { ...b.scope, attributes: redactKvs(b.scope.attributes, rules, "scope", hits) } : b.scope,
    spans: b.spans.map((s) => {
      // Span and event names often carry a URL or a tool argument, so they are redacted too,
      // and the hit labels use the redacted name so a preview never echoes the raw value.
      const name = redactString(s.name, rules, `span name [${s.spanId.slice(0, 6)}]`, hits);
      return {
        ...s,
        name,
        attributes: redactKvs(s.attributes, rules, `${name} [${s.spanId.slice(0, 6)}]`, hits),
        events: s.events.map((e) => {
          const eventName = redactString(e.name, rules, `${name} event name`, hits);
          return { ...e, name: eventName, attributes: redactKvs(e.attributes, rules, `${name} event ${eventName}`, hits) };
        }),
        links: s.links.map((l) => ({ ...l, attributes: redactKvs(l.attributes, rules, `${name} link`, hits) })),
        status: s.status.message ? { ...s.status, message: redactString(s.status.message, rules, `${name} status`, hits) } : s.status,
      };
    }),
  }));
  return { batches: out, hits };
}
